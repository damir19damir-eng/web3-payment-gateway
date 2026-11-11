package com.payments.gateway.fraud;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/**
 * Детектор аномалий в реальном времени (скользящие окна в памяти узла).
 * Сигналы: частота запросов с IP, провалы AEAD (подделка AAD/шифртекста), повторы (replay),
 * смена отпечатка ключа клиента, один клиент с множества IP, неудачные handshake.
 * Каждый сигнал даёт баллы; ≥50 — CHALLENGE (притормозить/доп. проверка), ≥100 — BLOCK.
 * Оповещения (Alert) уходят в sink — в проде это топик Kafka fraud.alerts.
 */
public final class AnomalyDetector {
    public enum Decision { ALLOW, CHALLENGE, BLOCK }

    public record Verdict(Decision decision, int score, List<String> reasons) {}

    public record Alert(String type, String ip, String clientId, int score, String detail, long tsMs) {}

    public record Config(int maxReqPerSecPerIp, int maxReqPerMinPerIp, int distinctIpsPerClient) {
        public static Config defaults() { return new Config(100, 2000, 5); }
    }

    private static final long SEC = 1_000, MIN = 60_000, FIVE_MIN = 300_000, TEN_MIN = 600_000, HOUR = 3_600_000;

    /** Скользящее окно меток времени. */
    private static final class Window {
        private final Deque<Long> times = new ArrayDeque<>();

        synchronized void add(long now, long keepMs) {
            prune(now, keepMs);
            times.addLast(now);
        }

        synchronized int count(long now, long windowMs) {
            int n = 0;
            for (var it = times.descendingIterator(); it.hasNext(); ) {
                if (now - it.next() > windowMs) break;
                n++;
            }
            return n;
        }

        synchronized boolean staleAfter(long now, long keepMs) {
            prune(now, keepMs);
            return times.isEmpty();
        }

        private void prune(long now, long keepMs) {
            while (!times.isEmpty() && now - times.peekFirst() > keepMs) times.pollFirst();
        }
    }

    private final Config cfg;
    private final LongSupplier clock;
    private final Consumer<Alert> sink;
    private final ConcurrentMap<String, Window> ipRequests = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Window> ipCryptoFailures = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Window> clientKeyChanges = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> lastFingerprint = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, ConcurrentMap<String, Long>> clientIps = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Decision> lastDecision = new ConcurrentHashMap<>();

    public AnomalyDetector(Config cfg, LongSupplier clock, Consumer<Alert> sink) {
        this.cfg = cfg;
        this.clock = clock;
        this.sink = sink;
    }

    /** Вызывается на каждый входящий запрос ДО расшифровки. */
    public Verdict onRequest(String ip, String clientId) {
        long now = clock.getAsLong();
        ipRequests.computeIfAbsent(ip, k -> new Window()).add(now, MIN);
        int score = 0;
        List<String> reasons = new ArrayList<>();

        if (ipRequests.get(ip).count(now, SEC) > cfg.maxReqPerSecPerIp()) { score += 60; reasons.add("ip_rate_1s"); }
        if (ipRequests.get(ip).count(now, MIN) > cfg.maxReqPerMinPerIp()) { score += 60; reasons.add("ip_rate_60s"); }

        Window failures = ipCryptoFailures.get(ip);
        int f = failures == null ? 0 : failures.count(now, FIVE_MIN);
        if (f > 0) { score += Math.min(100, 40 * f); reasons.add("crypto_failures=" + f); }

        if (clientId != null && !clientId.isEmpty()) {
            ConcurrentMap<String, Long> ips = clientIps.computeIfAbsent(clientId, k -> new ConcurrentHashMap<>());
            ips.put(ip, now);
            ips.values().removeIf(t -> now - t > TEN_MIN);
            if (ips.size() > cfg.distinctIpsPerClient()) { score += 40; reasons.add("client_ips=" + ips.size()); }

            Window kc = clientKeyChanges.get(clientId);
            int changes = kc == null ? 0 : kc.count(now, HOUR);
            if (changes > 0) { score += changes >= 2 ? 100 : 40; reasons.add("key_changes=" + changes); }
        }

        Decision d = score >= 100 ? Decision.BLOCK : score >= 50 ? Decision.CHALLENGE : Decision.ALLOW;
        Decision prev = lastDecision.put(ip, d);
        if (d != Decision.ALLOW && d != prev)
            sink.accept(new Alert("DECISION_" + d, ip, clientId, score, String.join(",", reasons), now));
        return new Verdict(d, score, reasons);
    }

    /** kind: AAD_TAMPER, REPLAY, HANDSHAKE_FAIL, ... */
    public void onCryptoFailure(String ip, String clientId, String kind) {
        long now = clock.getAsLong();
        ipCryptoFailures.computeIfAbsent(ip, k -> new Window()).add(now, FIVE_MIN);
        sink.accept(new Alert(kind, ip, clientId, 0, "", now));
    }

    /** @return true, если отпечаток ключа клиента изменился с прошлого раза. */
    public boolean onKeyFingerprint(String clientId, String fingerprint) {
        String prev = lastFingerprint.put(clientId, fingerprint);
        if (prev == null || prev.equals(fingerprint)) return false;
        long now = clock.getAsLong();
        clientKeyChanges.computeIfAbsent(clientId, k -> new Window()).add(now, HOUR);
        sink.accept(new Alert("KEY_FINGERPRINT_CHANGE", null, clientId, 0, prev + "->" + fingerprint, now));
        return true;
    }

    /** Периодическая очистка (вызывать из планировщика), чтобы окна не росли бесконечно. */
    public void evictStale() {
        long now = clock.getAsLong();
        ipRequests.entrySet().removeIf(e -> e.getValue().staleAfter(now, MIN));
        ipCryptoFailures.entrySet().removeIf(e -> e.getValue().staleAfter(now, FIVE_MIN));
        clientKeyChanges.entrySet().removeIf(e -> e.getValue().staleAfter(now, HOUR));
        lastDecision.keySet().removeIf(ip -> !ipRequests.containsKey(ip));
    }

    public Map<String, Integer> stats() {
        return Map.of("ips", ipRequests.size(), "clients", clientIps.size());
    }
}
