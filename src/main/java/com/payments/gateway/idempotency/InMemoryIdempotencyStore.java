package com.payments.gateway.idempotency;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.LongSupplier;

/** Эталонная реализация с теми же правилами, что и Lua-скрипты Redis (для тестов и локального запуска). */
public final class InMemoryIdempotencyStore implements IdempotencyStore {
    private static final class Entry {
        boolean done;
        String token, fingerprint, response;
        long expiresAt;
    }

    private final Map<String, Entry> map = new HashMap<>();
    private final LongSupplier nowMs;

    public InMemoryIdempotencyStore() { this(System::currentTimeMillis); }

    public InMemoryIdempotencyStore(LongSupplier nowMs) { this.nowMs = nowMs; }

    @Override
    public synchronized CompletionStage<Begin> begin(String key, String fingerprint, Duration lockTtl) {
        long now = nowMs.getAsLong();
        Entry e = map.get(key);
        if (e != null && e.expiresAt <= now) {
            map.remove(key);
            e = null;
        }
        if (e == null) {
            e = new Entry();
            e.token = UUID.randomUUID().toString();
            e.fingerprint = fingerprint;
            e.expiresAt = now + lockTtl.toMillis();
            map.put(key, e);
            return done(new Begin(Status.ACQUIRED, e.token, null));
        }
        if (!e.fingerprint.equals(fingerprint)) return done(new Begin(Status.CONFLICT, null, null));
        if (e.done) return done(new Begin(Status.DONE, null, e.response));
        return done(new Begin(Status.IN_PROGRESS, null, null));
    }

    @Override
    public synchronized CompletionStage<Boolean> complete(String key, String token, String response, Duration retention) {
        Entry e = map.get(key);
        if (e == null || !e.token.equals(token)) return done(false);
        e.done = true;
        e.response = response;
        e.expiresAt = nowMs.getAsLong() + retention.toMillis();
        return done(true);
    }

    @Override
    public synchronized CompletionStage<Boolean> abort(String key, String token) {
        Entry e = map.get(key);
        if (e == null || !e.token.equals(token) || e.done) return done(false);
        map.remove(key);
        return done(true);
    }

    private static <T> CompletionStage<T> done(T v) { return CompletableFuture.completedFuture(v); }
}
