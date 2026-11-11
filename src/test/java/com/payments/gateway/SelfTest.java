package com.payments.gateway;

import com.payments.gateway.crypto.Handshake;
import com.payments.gateway.crypto.Keys;
import com.payments.gateway.crypto.SecureSession;
import com.payments.gateway.crypto.SecureSession.ReplayException;
import com.payments.gateway.crypto.SessionRegistry;
import com.payments.gateway.fraud.AnomalyDetector;
import com.payments.gateway.fraud.AnomalyDetector.Decision;
import com.payments.gateway.idempotency.IdempotencyStore.Status;
import com.payments.gateway.idempotency.InMemoryIdempotencyStore;
import com.payments.gateway.shard.ShardRouter;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Проверки ядра без внешних зависимостей: java -cp out com.payments.gateway.SelfTest */
public class SelfTest {
    static int passed;

    static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        passed++;
        System.out.println("  ok  " + name);
    }

    interface Thrower { void run() throws Exception; }

    static <T extends Throwable> void expect(Class<T> type, Thrower t, String name) {
        try {
            t.run();
        } catch (Throwable e) {
            check(type.isInstance(e), name + " (" + e.getClass().getSimpleName() + ")");
            return;
        }
        throw new AssertionError("FAILED (no exception): " + name);
    }

    record Pair(SecureSession client, SecureSession server) {}

    static Pair handshake(KeyPair serverId, KeyPair clientId) throws Exception {
        long now = System.currentTimeMillis();
        Handshake.Client c = new Handshake.Client("acme", clientId.getPrivate(), serverId.getPublic());
        var hello = c.hello(now / 1000);
        var acc = Handshake.accept(hello, clientId.getPublic(), now / 1000, now);
        byte[] sig = Keys.sign(serverId.getPrivate(), acc.transcript());
        SecureSession cs = c.finish(new Handshake.ServerHello(acc.session().sid(), acc.serverEph(), sig), now);
        return new Pair(cs, acc.session());
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== E2EE: handshake + ratchet ==");
        KeyPair serverId = Keys.ed25519(), clientId = Keys.ed25519();
        Pair p = handshake(serverId, clientId);
        byte[] msg = "{\"from\":\"A\",\"to\":\"B\",\"amountMinor\":1500}".getBytes();
        var m0 = p.client().seal(msg, "idem-1");
        check(Arrays.equals(msg, p.server().open(m0.seq(), m0.ct(), "idem-1")), "запрос расшифрован сервером");
        var r0 = p.server().seal("{\"status\":\"ACCEPTED\"}".getBytes(), "idem-1");
        check(new String(p.client().open(r0.seq(), r0.ct(), "idem-1")).contains("ACCEPTED"), "ответ расшифрован клиентом");
        expect(ReplayException.class, () -> p.server().open(m0.seq(), m0.ct(), "idem-1"), "повтор (replay) отклонён");

        var m1 = p.client().seal(msg, "idem-2");
        expect(AEADBadTagException.class, () -> p.server().open(m1.seq(), m1.ct(), "idem-OTHER"), "подмена AAD (Idempotency-Key) отклонена");
        check(Arrays.equals(msg, p.server().open(m1.seq(), m1.ct(), "idem-2")), "после атаки сессия не рассинхронизирована");

        var m2 = p.client().seal(msg, "a");
        var m3 = p.client().seal(msg, "b");
        var m4 = p.client().seal(msg, "c");
        check(Arrays.equals(msg, p.server().open(m4.seq(), m4.ct(), "c")), "пропуск номеров (потерянные сообщения) допустим");
        expect(ReplayException.class, () -> p.server().open(m2.seq(), m2.ct(), "a"), "пропущенное сообщение уже нельзя расшифровать");

        var m5 = p.client().seal(msg, "d");
        byte[] bad = m5.ct().clone();
        bad[3] ^= 1;
        expect(GeneralSecurityException.class, () -> p.server().open(m5.seq(), bad, "d"), "изменённый шифртекст отклонён");
        var wrongDir = p.server().seal(msg, "x");
        expect(GeneralSecurityException.class, () -> p.server().open(wrongDir.seq(), wrongDir.ct(), "x"), "зеркальное сообщение (reflection) отклонено");

        Pair p2 = handshake(serverId, clientId);
        var n0 = p2.client().seal(msg, "idem-1");
        check(!Arrays.equals(n0.ct(), m0.ct()), "новая сессия = новые ключи (тот же текст — другой шифртекст)");
        expect(GeneralSecurityException.class, () -> p.server().open(n0.seq(), n0.ct(), "idem-1"), "шифртекст другой сессии не читается");

        KeyPair fakeServer = Keys.ed25519();
        Handshake.Client c = new Handshake.Client("acme", clientId.getPrivate(), fakeServer.getPublic());
        long now = System.currentTimeMillis();
        var hello = c.hello(now / 1000);
        var acc = Handshake.accept(hello, clientId.getPublic(), now / 1000, now);
        byte[] sig = Keys.sign(serverId.getPrivate(), acc.transcript());
        expect(GeneralSecurityException.class, () -> c.finish(new Handshake.ServerHello(acc.session().sid(), acc.serverEph(), sig), now), "клиент отвергает чужой сервер (pinning)");
        var h2 = new Handshake.Client("acme", Keys.ed25519().getPrivate(), serverId.getPublic()).hello(now / 1000);
        expect(GeneralSecurityException.class, () -> Handshake.accept(h2, clientId.getPublic(), now / 1000, now), "сервер отвергает чужую подпись клиента");
        expect(GeneralSecurityException.class, () -> Handshake.accept(hello, clientId.getPublic(), now / 1000 + 3600, now), "устаревший hello отклонён");

        SessionRegistry reg = new SessionRegistry(1000, 3);
        reg.put(p2.server());
        check(reg.get(p2.server().sid(), p2.server().createdAtMs() + 10) != null, "сессия найдена");
        check(reg.get(p2.server().sid(), p2.server().createdAtMs() + 5000) == null, "сессия истекла по TTL");

        System.out.println("== Идемпотентность ==");
        AtomicLong clock = new AtomicLong(1_000);
        var store = new InMemoryIdempotencyStore(clock::get);
        Duration ttl = Duration.ofSeconds(30);
        var b1 = store.begin("k1", "fp1", ttl).toCompletableFuture().get();
        check(b1.status() == Status.ACQUIRED, "первый запрос получает замок");
        check(store.begin("k1", "fp1", ttl).toCompletableFuture().get().status() == Status.IN_PROGRESS, "повтор во время обработки -> IN_PROGRESS");
        check(store.begin("k1", "OTHER", ttl).toCompletableFuture().get().status() == Status.CONFLICT, "тот же ключ, другое тело -> CONFLICT");
        check(!store.complete("k1", "wrong-token", "x", ttl).toCompletableFuture().get(), "чужой токен не может завершить платёж");
        check(store.complete("k1", b1.token(), "{\"ok\":1}", Duration.ofHours(24)).toCompletableFuture().get(), "владелец завершает платёж");
        var again = store.begin("k1", "fp1", ttl).toCompletableFuture().get();
        check(again.status() == Status.DONE && again.response().equals("{\"ok\":1}"), "повтор после успеха -> тот же ответ, без нового списания");
        var b2 = store.begin("k2", "fp", ttl).toCompletableFuture().get();
        store.abort("k2", b2.token()).toCompletableFuture().get();
        check(store.begin("k2", "fp", ttl).toCompletableFuture().get().status() == Status.ACQUIRED, "после abort можно повторить");
        ExecutorService pool = Executors.newFixedThreadPool(32);
        AtomicInteger winners = new AtomicInteger();
        List<CompletableFuture<Void>> fs = new ArrayList<>();
        for (int i = 0; i < 500; i++)
            fs.add(CompletableFuture.runAsync(() -> {
                try {
                    if (store.begin("race", "fp", ttl).toCompletableFuture().get().status() == Status.ACQUIRED) winners.incrementAndGet();
                } catch (Exception e) { throw new RuntimeException(e); }
            }, pool));
        CompletableFuture.allOf(fs.toArray(new CompletableFuture[0])).get();
        pool.shutdown();
        check(winners.get() == 1, "500 параллельных запросов -> ровно один выигрывает замок");

        System.out.println("== Шардирование ==");
        ShardRouter r4 = new ShardRouter(4, 128), r5 = new ShardRouter(5, 128);
        int[] load = new int[4];
        int moved = 0, movedToNew = 0, n = 100_000;
        for (int i = 0; i < n; i++) {
            String account = "acc-" + i;
            int s4 = r4.shardFor(account), s5 = r5.shardFor(account);
            load[s4]++;
            if (s4 != s5) { moved++; if (s5 == 4) movedToNew++; }
        }
        double mean = n / 4.0;
        boolean even = Arrays.stream(load).allMatch(x -> Math.abs(x - mean) / mean < 0.25);
        check(even, "равномерность по 4 шардам " + Arrays.toString(load));
        check(moved < n * 0.30 && moved == movedToNew, "добавление 5-го шарда переносит " + moved * 100 / n + "% ключей, и только на новый шард");
        check(r4.shardFor("acc-42") == r4.shardFor("acc-42"), "маршрутизация детерминирована");

        System.out.println("== Антифрод ==");
        AtomicLong t = new AtomicLong(1_000_000);
        List<AnomalyDetector.Alert> alerts = new ArrayList<>();
        var det = new AnomalyDetector(AnomalyDetector.Config.defaults(), t::get, alerts::add);
        check(det.onRequest("1.1.1.1", "acme").decision() == Decision.ALLOW, "обычный запрос разрешён");
        Decision d = Decision.ALLOW;
        for (int i = 0; i < 150; i++) d = det.onRequest("2.2.2.2", "bot").decision();
        check(d == Decision.CHALLENGE, "всплеск >100 запросов/с с одного IP -> CHALLENGE");
        t.addAndGet(2_000);
        check(det.onRequest("2.2.2.2", "bot").decision() == Decision.ALLOW, "через пару секунд ограничение снимается");
        det.onCryptoFailure("3.3.3.3", "acme", "AAD_TAMPER");
        det.onCryptoFailure("3.3.3.3", "acme", "AAD_TAMPER");
        check(det.onRequest("3.3.3.3", "acme").decision() == Decision.CHALLENGE, "2 провала AEAD подряд -> CHALLENGE");
        det.onCryptoFailure("3.3.3.3", "acme", "AAD_TAMPER");
        check(det.onRequest("3.3.3.3", "acme").decision() == Decision.BLOCK, "3 провала AEAD -> BLOCK");
        t.addAndGet(301_000);
        check(det.onRequest("3.3.3.3", "acme").decision() == Decision.ALLOW, "блокировка истекает через 5 минут");
        check(!det.onKeyFingerprint("corp", "fpA"), "первый отпечаток запоминается");
        check(det.onKeyFingerprint("corp", "fpB"), "смена отпечатка ключа обнаружена");
        check(det.onRequest("4.4.4.4", "corp").score() == 40, "смена ключа добавляет баллы риска");
        for (int i = 0; i < 7; i++) det.onRequest("10.0.0." + i, "roaming");
        check(det.onRequest("10.0.0.9", "roaming").reasons().stream().anyMatch(s -> s.startsWith("client_ips")), "один клиент с множества IP отмечен");
        check(alerts.stream().anyMatch(a -> a.type().equals("AAD_TAMPER")) && alerts.stream().anyMatch(a -> a.type().equals("KEY_FINGERPRINT_CHANGE")), "оповещения отправлены в sink");

        System.out.println("\nВсе проверки пройдены: " + passed);
    }
}
