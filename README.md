# Cryptographic Payment Gateway

A payment gateway in Java 17 on Spring Boot WebFlux. Clients connect over mTLS, establish an end-to-end encrypted session with ephemeral keys (X25519, Ed25519, HKDF, AES-256-GCM), and send payments that are idempotent and sharded across PostgreSQL. Payment events leave through a transactional outbox into Kafka, where a credit consumer and a hash-chained audit consumer process them.

> **Status:** The cryptographic core, sharding, and fraud logic pass a 38-check self-test. The Spring layer (web, config, ledger, messaging, Redis with Lua scripts, and Vault adapters) has been successfully compiled, run, and verified against local Docker infrastructure (PostgreSQL, Redis, Kafka). See [Status](#status).

## Architecture

    Client ──mTLS──► LB (sticky by sid) ──► Gateway (WebFlux, Netty)
                                             │ 1. handshake: X25519 + Ed25519, transcript signed by Vault Transit
                                             │ 2. E2EE: key ratchet + AES-256-GCM, AAD = sid|direction|seq|Idempotency-Key
                                             │ 3. fraud checks before decryption (IP rate, AEAD failures, key changes)
                                             │ 4. Redis: Idempotency-Key + lock (Lua)
                                             ▼
                           PostgreSQL shards (consistent hashing by sender account)
                             one transaction: payments (UNIQUE key) + debit + outbox
                                             │ OutboxRelay (at-least-once, acks=all)
                                             ▼
                                           Kafka ──► credit-consumer (recipient shard, idempotent)
                                                 └─► audit-consumer  (hash chain, append-only)

## Components

| Requirement | Implementation |
|---|---|
| Reactive backend | `web/GatewayController`, WebFlux + R2DBC + reactive Redis |
| Sharding | `shard/ShardRouter` (ring, 128 virtual nodes), `config/Shards` (connection pool per shard) |
| Replication | Infrastructure level: PostgreSQL (Patroni, synchronous replica in another data center), Redis Cluster, Kafka `replication.factor=3`, `min.insync.replicas=2` |
| mTLS | `application.yml` (`client-auth: need`), `scripts/gen-certs.sh` |
| E2EE and PFS | `crypto/Handshake`, `crypto/SecureSession` |
| Secrets in Vault | `keys/VaultKeyProvider` (Transit engine: the signing private key never leaves Vault) |
| Idempotency and lock | `idempotency/*` (Lua script in `resources/lua/rate_limit.lua`) and `UNIQUE(idempotency_key)` in PostgreSQL |
| Broker, at-least-once | `OutboxRelay` and `EventConsumers`, manual offset commit |
| Audit | `audit_log`: hash chain plus a trigger that blocks updates and deletes |
| Fraud detection | `fraud/AnomalyDetector` publishes alerts to the `fraud.alerts` topic |

## Cryptographic protocol

1. **Handshake** (once per payment session). The client sends an ephemeral X25519 public key, an Ed25519 signature, and a timestamp. The server verifies the signature against the client registry, creates its own ephemeral key, and signs the transcript with the key held in Vault. The client verifies that signature against the server key it has pinned.
2. **Keys.** `HKDF(ECDH, SHA-256(transcript))` produces two chains, one per direction. Ephemeral private keys are discarded after use, which gives perfect forward secrecy (PFS).
3. **Per-message keys.** Each message gets a one-time key (`chainKey → messageKey, nextChainKey`), and the old chain key is overwritten. A session lasts 15 minutes or 1000 messages, after which a new handshake runs with new ephemeral keys.
4. **AAD** covers `sid | direction | seq | Idempotency-Key`. Changing any field makes the GCM tag fail, which raises an `AAD_TAMPER` signal for fraud detection.
5. **Replay protection.** `seq` strictly increases. A gap of up to 256 numbers is accepted (for lost requests), and older numbers are rejected. Invalid messages do not advance session state.

This is not the full Signal protocol. There is no DH ratchet inside a session. Post-compromise security comes from starting a new handshake.

## Running the project

### 0. Core self-test (JDK 17+, no Maven)

    mkdir -p out && javac -d out $(find src/main/java/com/payments/gateway/{crypto,fraud,shard} -name '*.java') \
      src/main/java/com/payments/gateway/keys/{KeyProvider,LocalKeyProvider}.java \
      src/main/java/com/payments/gateway/idempotency/{IdempotencyStore,InMemoryIdempotencyStore}.java \
      src/main/java/com/payments/gateway/client/DemoClient.java src/test/java/com/payments/gateway/SelfTest.java
    java -cp out com.payments.gateway.SelfTest

### 1. Infrastructure and certificates

    docker compose up -d
    ./scripts/gen-certs.sh
    docker compose exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=dev-root vault sh -c \
      "vault secrets enable transit && vault write transit/keys/gateway-signing type=ed25519"
    docker compose exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --topic payments.initiated --partitions 6
    docker compose exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --topic fraud.alerts --partitions 3

### 2. Client key

Generate the client key pair and copy the public part into `application.yml` under `gateway.clients.acme`:

    java -cp out com.payments.gateway.client.DemoClient

### 3. Gateway

    VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-root mvn spring-boot:run

The log prints `Публичный ключ сервера` (server public key). Copy that value and use it as `SERVER_PUB`.

### 4. Client (mTLS through JVM system properties)

    export CLIENT_KEY_PKCS8=... SERVER_PUB=...
    java -Djavax.net.ssl.keyStore=certs/client.p12 -Djavax.net.ssl.keyStorePassword=changeit \
         -Djavax.net.ssl.trustStore=certs/ca.p12 -Djavax.net.ssl.trustStorePassword=changeit \
         -cp out com.payments.gateway.client.DemoClient

The demo client sends a payment and then retries it with the same `Idempotency-Key`. The retry gets the same response, and the balance is debited once.

## Idempotency

A payment is identified by its `Idempotency-Key`. The gateway checks Redis first, using an atomic Lua script (`rate_limit.lua`) that takes a lock. PostgreSQL then enforces the same rule with a UNIQUE constraint, in the same transaction as the debit and the outbox row. Redis is not the source of truth. If Redis loses a write during failover, the database constraint still rejects the duplicate.

The self-test covers 500 concurrent requests with the same key. Exactly one request wins.

## Status

Verified by running the self-test (38 checks) and local Spring Boot integration:

- Handshake and mutual authentication.
- Encryption and decryption.
- Rejection of tampered AAD, forged ciphertext, replayed messages, a wrong server key, a wrong client key, and a stale hello.
- Idempotency, including 500 parallel requests.
- Shard distribution and stability.
- Fraud rules.
- **Spring Boot Layer & Infrastructure:** Successfully compiled, initialized, and verified with real PostgreSQL shards, Redis (including Lua script execution), and Kafka message brokers (`GatewayApplication` running cleanly on Java 21 / Spring Boot 3.3.5).

Not measured:

- Latency below 10 ms and throughput in thousands of requests per second. Use load testing (Gatling or k6) on your own infrastructure to get numbers.

## Before production

- **Data center failure and consistency.** The guarantee that no transaction is lost depends on PostgreSQL synchronous replication (`synchronous_commit=on` with a synchronous standby in another data center) and Kafka `acks=all`. Redis is not the source of truth.
- **Sessions** live in node memory, so the load balancer must route by `sid`, or the chain state must move to Redis.
- **Sagas.** If the recipient account is not found, the event should go to a dead-letter topic and trigger a refund to the sender. The code currently only logs an error and retries.
- **Server identity.** Clients pin the server public key. Rotating that key in Vault requires a process for distributing the new key.
- **Vault.** Replace the static token with AppRole or Kubernetes auth, and use TLS to Vault. Use `spring.ssl.bundle` for mTLS to PostgreSQL, Redis, and Kafka.
- **Fraud detection.** Counters live in node memory. A cluster needs aggregation in Redis or Flink, plus ML scoring on top of these signals.
- **Audit.** One hash chain on shard 0 means one consumer. To scale, use a chain per partition and periodically sign the chain head, anchored in external storage.
- **Not covered by this framework:** request body validation and limits, idempotency on the recipient side, and PCI DSS or local regulatory compliance.