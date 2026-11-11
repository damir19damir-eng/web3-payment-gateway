package com.payments.gateway.messaging;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.payments.gateway.config.Shards;
import com.payments.gateway.crypto.Keys;
import com.payments.gateway.ledger.Payments.PaymentEvent;
import com.payments.gateway.shard.ShardRouter;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;

/**
 * Потребители Kafka (offset фиксируется вручную ПОСЛЕ обработки = at-least-once).
 *  - credit: зачисление на шард получателя; таблица processed_events делает его идемпотентным,
 *    поэтому повторная доставка не зачислит деньги дважды (эффект «ровно один раз»).
 *  - audit: журнал с хеш-цепочкой (hash_n = SHA-256(hash_{n-1} | запись)): правка или удаление
 *    любой записи ломает цепочку; плюс триггер append-only в БД. Один поток (concurrency=1) = одна цепочка.
 * Постоянные ошибки (нет счёта получателя) нужно уводить в DLT и делать компенсацию — см. README.
 */
@Component
public class EventConsumers {
    private final Shards shards;
    private final ShardRouter router;
    private final ObjectMapper mapper;

    public EventConsumers(Shards shards, ShardRouter router, ObjectMapper mapper) {
        this.shards = shards;
        this.router = router;
        this.mapper = mapper;
    }

    @KafkaListener(topics = "payments.initiated", groupId = "ledger-credit")
    public void credit(String payload, Acknowledgment ack) throws Exception {
        PaymentEvent e = mapper.readValue(payload, PaymentEvent.class);
        Shards.Shard sh = shards.get(router.shardFor(e.dst()));
        sh.tx().transactional(
                sh.db().sql("INSERT INTO processed_events(event_id) VALUES (:id) ON CONFLICT DO NOTHING")
                        .bind("id", UUID.fromString(e.paymentId())).fetch().rowsUpdated()
                        .flatMap(n -> n == 0
                                ? Mono.just(0L) // уже обработано — повторная доставка
                                : sh.db().sql("UPDATE accounts SET balance = balance + :a WHERE id = :dst AND currency = :cur")
                                .bind("a", e.amountMinor()).bind("dst", e.dst()).bind("cur", e.currency())
                                .fetch().rowsUpdated()
                                .flatMap(u -> u == 1 ? Mono.just(u)
                                        : Mono.<Long>error(new IllegalStateException("счёт получателя не найден: " + e.dst()))))
        ).block(Duration.ofSeconds(5));
        ack.acknowledge();
    }

    @KafkaListener(topics = {"payments.initiated", "fraud.alerts"}, groupId = "audit", concurrency = "1")
    public void audit(ConsumerRecord<String, String> rec, Acknowledgment ack) {
        Shards.Shard sh = shards.get(0);
        sh.tx().transactional(
                sh.db().sql("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE")
                        .map(r -> r.get("hash", String.class)).one().defaultIfEmpty("GENESIS")
                        .flatMap(prev -> {
                            String line = prev + "|" + rec.topic() + "|" + rec.partition() + "|" + rec.offset() + "|" + rec.value();
                            String hash = Keys.hex(Keys.sha256(line.getBytes(StandardCharsets.UTF_8)));
                            return sh.db().sql("""
                                            INSERT INTO audit_log(topic, kafka_partition, kafka_offset, payload, prev_hash, hash)
                                            VALUES (:t, :p, :o, :pl, :prev, :h)
                                            ON CONFLICT (topic, kafka_partition, kafka_offset) DO NOTHING""")
                                    .bind("t", rec.topic()).bind("p", rec.partition()).bind("o", rec.offset())
                                    .bind("pl", rec.value()).bind("prev", prev).bind("h", hash)
                                    .fetch().rowsUpdated();
                        })
        ).block(Duration.ofSeconds(5));
        ack.acknowledge();
    }
}
