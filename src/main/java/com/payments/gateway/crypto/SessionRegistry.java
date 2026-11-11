package com.payments.gateway.crypto;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Реестр активных сессий в памяти узла. Сессия живёт ограниченное время и ограниченное число сообщений —
 * после этого клиент делает новый handshake (новые эфемерные ключи = ротация).
 * В кластере LB должен направлять запросы одной сессии на один узел (sticky по sid/clientId),
 * иначе придётся хранить состояние цепочек в Redis.
 */
public final class SessionRegistry {
    private final ConcurrentMap<String, SecureSession> sessions = new ConcurrentHashMap<>();
    private final long ttlMs;
    private final long maxMessages;

    public SessionRegistry(long ttlMs, long maxMessages) {
        this.ttlMs = ttlMs;
        this.maxMessages = maxMessages;
    }

    public void put(SecureSession s) { sessions.put(s.sid(), s); }

    /** @return сессия или null, если её нет / она истекла / исчерпала лимит сообщений */
    public SecureSession get(String sid, long nowMs) {
        SecureSession s = sessions.get(sid);
        if (s == null) return null;
        if (expired(s, nowMs)) {
            sessions.remove(sid, s);
            return null;
        }
        return s;
    }

    public int sweep(long nowMs) {
        int before = sessions.size();
        sessions.values().removeIf(s -> expired(s, nowMs));
        return before - sessions.size();
    }

    public int size() { return sessions.size(); }

    private boolean expired(SecureSession s, long nowMs) {
        return nowMs - s.createdAtMs() > ttlMs || s.messages() >= maxMessages;
    }
}
