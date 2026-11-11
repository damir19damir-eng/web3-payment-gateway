package com.payments.gateway.idempotency;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletionStage;

/**
 * Те же правила, что у InMemoryIdempotencyStore, но атомарно на стороне Redis (Lua).
 * Запись: hash {state: P|D, token, fp, resp} с TTL. Один ключ на скрипт — работает и в Redis Cluster.
 * ВАЖНО: Redis при failover может потерять последнюю запись (асинхронная репликация), поэтому
 * окончательный «замок» — UNIQUE(idempotency_key) в Postgres: второе списание невозможно в любом случае.
 */
@SuppressWarnings({"rawtypes", "unchecked"})
public final class RedisIdempotencyStore implements IdempotencyStore {
    private static final RedisScript<List> BEGIN = RedisScript.of("""
            local v = redis.call('HMGET', KEYS[1], 'state', 'fp', 'resp')
            if not v[1] then
              redis.call('HSET', KEYS[1], 'state', 'P', 'token', ARGV[2], 'fp', ARGV[1])
              redis.call('PEXPIRE', KEYS[1], ARGV[3])
              return {'ACQUIRED', ARGV[2]}
            end
            if v[2] ~= ARGV[1] then return {'CONFLICT'} end
            if v[1] == 'D' then return {'DONE', v[3]} end
            return {'IN_PROGRESS'}
            """, List.class);

    private static final RedisScript<Long> COMPLETE = RedisScript.of("""
            if redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return 0 end
            redis.call('HSET', KEYS[1], 'state', 'D', 'resp', ARGV[2])
            redis.call('PEXPIRE', KEYS[1], ARGV[3])
            return 1
            """, Long.class);

    private static final RedisScript<Long> ABORT = RedisScript.of("""
            if redis.call('HGET', KEYS[1], 'token') == ARGV[1] and redis.call('HGET', KEYS[1], 'state') == 'P' then
              return redis.call('DEL', KEYS[1])
            end
            return 0
            """, Long.class);

    private final ReactiveStringRedisTemplate redis;

    public RedisIdempotencyStore(ReactiveStringRedisTemplate redis) { this.redis = redis; }

    private static String k(String key) { return "idem:{" + key + "}"; }

    @Override
    public CompletionStage<Begin> begin(String key, String fingerprint, Duration lockTtl) {
        String token = UUID.randomUUID().toString();
        return redis.execute(BEGIN, List.of(k(key)), List.of(fingerprint, token, Long.toString(lockTtl.toMillis())))
                .next()
                .map(r -> {
                    List<?> l = (List<?>) r;
                    return switch (String.valueOf(l.get(0))) {
                        case "ACQUIRED" -> new Begin(Status.ACQUIRED, token, null);
                        case "DONE" -> new Begin(Status.DONE, null, String.valueOf(l.get(1)));
                        case "IN_PROGRESS" -> new Begin(Status.IN_PROGRESS, null, null);
                        default -> new Begin(Status.CONFLICT, null, null);
                    };
                })
                .toFuture();
    }

    @Override
    public CompletionStage<Boolean> complete(String key, String token, String response, Duration retention) {
        return redis.execute(COMPLETE, List.of(k(key)), List.of(token, response, Long.toString(retention.toMillis())))
                .next().map(n -> n == 1L).toFuture();
    }

    @Override
    public CompletionStage<Boolean> abort(String key, String token) {
        return redis.execute(ABORT, List.of(k(key)), List.of(token)).next().map(n -> n == 1L).toFuture();
    }
}
