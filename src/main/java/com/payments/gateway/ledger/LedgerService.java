package com.payments.gateway.ledger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.payments.gateway.config.Shards;
import com.payments.gateway.ledger.Payments.PaymentEvent;
import com.payments.gateway.ledger.Payments.PaymentRequest;
import com.payments.gateway.ledger.Payments.PaymentResult;
import com.payments.gateway.shard.ShardRouter;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Списание со счёта отправителя в ОДНОЙ транзакции его шарда:
 *   1) запись платежа (UNIQUE по idempotency_key — защита от двойного списания даже при сбое Redis),
 *   2) атомарный debit (UPDATE ... WHERE balance >= amount — без блокировок «прочитал-проверил-записал»),
 *   3) событие в outbox (Transactional Outbox: событие не потеряется, даже если Kafka недоступна).
 * Зачисление на шард получателя делает потребитель Kafka идемпотентно (сага, без 2PC).
 */
@Service
public class LedgerService {
    private final Shards shards;
    private final ShardRouter router;
    private final ObjectMapper mapper;

    public LedgerService(Shards shards, ShardRouter router, ObjectMapper mapper) {
        this.shards = shards;
        this.router = router;
        this.mapper = mapper;
    }

    public Mono<PaymentResult> transfer(PaymentRequest r, String idempotencyKey) {
        Shards.Shard sh = shards.get(router.shardFor(r.from()));
        UUID id = UUID.randomUUID();
        Mono<PaymentResult> work = sh.db().sql("""
                        INSERT INTO payments(id, idempotency_key, src, dst, amount, currency, status)
                        VALUES (:id, :k, :src, :dst, :amt, :cur, 'PENDING')
                        ON CONFLICT (idempotency_key) DO NOTHING""")
                .bind("id", id).bind("k", idempotencyKey).bind("src", r.from()).bind("dst", r.to())
                .bind("amt", r.amountMinor()).bind("cur", r.currency())
                .fetch().rowsUpdated()
                .flatMap(n -> n == 0 ? existing(sh, idempotencyKey) : debit(sh, id, r));
        return sh.tx().transactional(work);
    }

    private Mono<PaymentResult> debit(Shards.Shard sh, UUID id, PaymentRequest r) {
        return sh.db().sql("""
                        UPDATE accounts SET balance = balance - :amt
                        WHERE id = :src AND currency = :cur AND balance >= :amt""")
                .bind("amt", r.amountMinor()).bind("src", r.from()).bind("cur", r.currency())
                .fetch().rowsUpdated()
                .flatMap(n -> {
                    boolean ok = n == 1;
                    String status = ok ? "ACCEPTED" : "REJECTED";
                    Mono<Long> setStatus = sh.db().sql("UPDATE payments SET status = :s WHERE id = :id")
                            .bind("s", status).bind("id", id).fetch().rowsUpdated();
                    Mono<Long> outbox = ok ? enqueue(sh, id, r) : Mono.just(0L);
                    return setStatus.then(outbox).thenReturn(new PaymentResult(id.toString(), status));
                });
    }

    private Mono<Long> enqueue(Shards.Shard sh, UUID id, PaymentRequest r) {
        return Mono.fromCallable(() -> mapper.writeValueAsString(
                        new PaymentEvent(id.toString(), r.from(), r.to(), r.amountMinor(), r.currency())))
                .flatMap(json -> sh.db().sql("""
                                INSERT INTO outbox(id, topic, msg_key, payload)
                                VALUES (:id, 'payments.initiated', :key, :p)""")
                        .bind("id", UUID.randomUUID()).bind("key", id.toString()).bind("p", json)
                        .fetch().rowsUpdated());
    }

    private Mono<PaymentResult> existing(Shards.Shard sh, String idempotencyKey) {
        return sh.db().sql("SELECT id, status FROM payments WHERE idempotency_key = :k")
                .bind("k", idempotencyKey)
                .map(row -> new PaymentResult(String.valueOf(row.get("id")), row.get("status", String.class)))
                .one();
    }
}
