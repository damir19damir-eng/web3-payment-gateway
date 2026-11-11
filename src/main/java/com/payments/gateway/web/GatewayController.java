package com.payments.gateway.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.payments.gateway.config.ClientDirectory;
import com.payments.gateway.crypto.Handshake;
import com.payments.gateway.crypto.Keys;
import com.payments.gateway.crypto.SecureSession;
import com.payments.gateway.crypto.SessionRegistry;
import com.payments.gateway.fraud.AnomalyDetector;
import com.payments.gateway.idempotency.IdempotencyStore;
import com.payments.gateway.keys.KeyProvider;
import com.payments.gateway.ledger.LedgerService;
import com.payments.gateway.ledger.Payments.PaymentRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * POST /v1/handshake — аутентифицированный обмен ключами (новая сессия = новые эфемерные ключи).
 * POST /v1/payments  — зашифрованный платёж; Idempotency-Key входит в AAD, поэтому его нельзя подменить.
 * Канал уже защищён mTLS; E2EE поверх него защищает тело сообщения от промежуточных узлов (LB, прокси, логи).
 */
@RestController
@RequestMapping("/v1")
public class GatewayController {
    private static final Duration LOCK_TTL = Duration.ofSeconds(30);
    private static final Duration RETENTION = Duration.ofHours(24);

    private final KeyProvider keys;
    private final ClientDirectory directory;
    private final SessionRegistry sessions;
    private final IdempotencyStore idempotency;
    private final AnomalyDetector detector;
    private final LedgerService ledger;
    private final ObjectMapper mapper;

    public GatewayController(KeyProvider keys, ClientDirectory directory, SessionRegistry sessions,
                             IdempotencyStore idempotency, AnomalyDetector detector,
                             LedgerService ledger, ObjectMapper mapper) {
        this.keys = keys;
        this.directory = directory;
        this.sessions = sessions;
        this.idempotency = idempotency;
        this.detector = detector;
        this.ledger = ledger;
        this.mapper = mapper;
    }

    @PostMapping("/handshake")
    public Mono<Map<String, String>> handshake(@RequestBody Map<String, String> body, ServerWebExchange ex) {
        String ip = ip(ex);
        String clientId = body.getOrDefault("clientId", "");
        guard(detector.onRequest(ip, clientId));

        PublicKey identity = directory.get(clientId);
        if (identity == null) {
            detector.onCryptoFailure(ip, clientId, "HANDSHAKE_FAIL");
            return Mono.error(status(HttpStatus.UNAUTHORIZED, "unknown client"));
        }
        detector.onKeyFingerprint(clientId, Keys.fingerprint(identity));

        Handshake.Accepted accepted;
        try {
            var hello = new Handshake.ClientHello(clientId, dec(body.get("eph")), Long.parseLong(body.get("ts")), dec(body.get("sig")));
            accepted = Handshake.accept(hello, identity, Instant.now().getEpochSecond(), System.currentTimeMillis());
        } catch (GeneralSecurityException | RuntimeException e) {
            detector.onCryptoFailure(ip, clientId, "HANDSHAKE_FAIL");
            return Mono.error(status(HttpStatus.UNAUTHORIZED, "handshake rejected"));
        }
        Handshake.Accepted acc = accepted;
        // подпись транскрипта делает Vault: приватный ключ сервера в памяти шлюза отсутствует
        return Mono.fromCompletionStage(keys.sign(acc.transcript())).map(sig -> {
            sessions.put(acc.session());
            return Map.of("sid", acc.session().sid(), "eph", enc(acc.serverEph()), "sig", enc(sig));
        });
    }

    @PostMapping("/payments")
    public Mono<Map<String, String>> pay(@RequestHeader("Idempotency-Key") String idemKey,
                                         @RequestBody Map<String, String> env, ServerWebExchange ex) {
        String ip = ip(ex);
        SecureSession session = sessions.get(env.getOrDefault("sid", ""), System.currentTimeMillis());
        if (session == null) return Mono.error(status(HttpStatus.UNAUTHORIZED, "session expired: repeat handshake"));
        String clientId = session.clientId();
        guard(detector.onRequest(ip, clientId));

        byte[] plain;
        try {
            plain = session.open(Long.parseLong(env.get("seq")), dec(env.get("ct")), idemKey);
        } catch (SecureSession.ReplayException e) {
            detector.onCryptoFailure(ip, clientId, "REPLAY");
            return Mono.error(status(HttpStatus.BAD_REQUEST, "replay"));
        } catch (GeneralSecurityException | RuntimeException e) {
            detector.onCryptoFailure(ip, clientId, "AAD_TAMPER"); // тег GCM не сошёлся: подделка AAD/шифртекста
            return Mono.error(status(HttpStatus.BAD_REQUEST, "decryption failed"));
        }

        PaymentRequest req;
        try {
            req = mapper.readValue(plain, PaymentRequest.class);
        } catch (Exception e) {
            return Mono.error(status(HttpStatus.BAD_REQUEST, "malformed payment"));
        }
        if (req.amountMinor() <= 0 || req.from() == null || req.to() == null || req.from().equals(req.to())
                || req.currency() == null || req.currency().length() != 3)
            return Mono.error(status(HttpStatus.UNPROCESSABLE_ENTITY, "invalid payment"));

        String scopedKey = clientId + ":" + idemKey; // ключи разных клиентов не пересекаются
        String fingerprint = Keys.hex(Keys.sha256(plain));

        return Mono.fromCompletionStage(idempotency.begin(scopedKey, fingerprint, LOCK_TTL))
                .flatMap(b -> process(b, session, idemKey, scopedKey, req));
    }

    private Mono<Map<String, String>> process(IdempotencyStore.Begin b, SecureSession session, String idemKey,
                                              String scopedKey, PaymentRequest req) {
        switch (b.status()) {
            case DONE: // повтор: тот же ответ, без нового списания
                return Mono.just(reply(session, b.response(), idemKey));
            case IN_PROGRESS:
                return Mono.error(status(HttpStatus.CONFLICT, "request in progress"));
            case CONFLICT:
                return Mono.error(status(HttpStatus.UNPROCESSABLE_ENTITY, "idempotency key reused with different body"));
            default: // ACQUIRED — мы владелец замка
                return ledger.transfer(req, scopedKey)
                        .flatMap(result -> {
                            String json = write(result);
                            return Mono.fromCompletionStage(idempotency.complete(scopedKey, b.token(), json, RETENTION))
                                    .map(ok -> reply(session, json, idemKey));
                        })
                        .onErrorResume(err -> Mono.fromCompletionStage(idempotency.abort(scopedKey, b.token()))
                                .then(Mono.<Map<String, String>>error(err)));
        }
    }

    private Map<String, String> reply(SecureSession s, String json, String idemKey) {
        try {
            SecureSession.Sealed sealed = s.seal(json.getBytes(StandardCharsets.UTF_8), idemKey);
            return Map.of("sid", s.sid(), "seq", Long.toString(sealed.seq()), "ct", enc(sealed.ct()));
        } catch (GeneralSecurityException e) {
            throw status(HttpStatus.INTERNAL_SERVER_ERROR, "encryption failed");
        }
    }

    private String write(Object o) {
        try {
            return mapper.writeValueAsString(o);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void guard(AnomalyDetector.Verdict v) {
        if (v.decision() == AnomalyDetector.Decision.BLOCK) throw status(HttpStatus.FORBIDDEN, "blocked");
        if (v.decision() == AnomalyDetector.Decision.CHALLENGE) throw status(HttpStatus.TOO_MANY_REQUESTS, "slow down");
    }

    /** За балансировщиком используйте адрес из X-Forwarded-For только от доверенных прокси. */
    private static String ip(ServerWebExchange ex) {
        InetSocketAddress a = ex.getRequest().getRemoteAddress();
        return a == null ? "unknown" : a.getAddress().getHostAddress();
    }

    private static ResponseStatusException status(HttpStatus s, String reason) { return new ResponseStatusException(s, reason); }

    private static byte[] dec(String b64) { return Base64.getDecoder().decode(b64); }

    private static String enc(byte[] b) { return Base64.getEncoder().encodeToString(b); }
}
