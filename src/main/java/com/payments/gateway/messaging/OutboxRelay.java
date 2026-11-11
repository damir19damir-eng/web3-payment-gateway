package com.payments.gateway.messaging;

import com.payments.gateway.config.Shards;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.UUID;

/**
 * Переносит события из outbox в Kafka: at-least-once.
 * Строки помечаются published только ПОСЛЕ подтверждения брокера (acks=all, idempotent producer);
 * при сбое транзакция откатывается и отправка повторяется — возможны дубли, но не потери.
 * FOR UPDATE SKIP LOCKED позволяет нескольким экземплярам шлюза работать параллельно.
 */
@Component
public class OutboxRelay {
    private static final Logger log = LoggerFactory.getLogger(OutboxRelay.class);

    private record Row(UUID id, String topic, String key, String payload) {}

    private final Shards shards;
    private final KafkaTemplate<String, String> kafka;

    public OutboxRelay(Shards shards, KafkaTemplate<String, String> kafka) {
        this.shards = shards;
        this.kafka = kafka;
    }

    @Scheduled(fixedDelay = 100)
    public void relay() {
        for (Shards.Shard sh : shards.all()) {
            try {
                Long sent = sh.tx().transactional(
                                sh.db().sql("""
                                                SELECT id, topic, msg_key, payload FROM outbox
                                                WHERE NOT published ORDER BY created_at
                                                LIMIT 200 FOR UPDATE SKIP LOCKED""")
                                        .map(row -> new Row(row.get("id", UUID.class), row.get("topic", String.class),
                                                row.get("msg_key", String.class), row.get("payload", String.class)))
                                        .all()
                                        .concatMap(o -> Mono.fromFuture(kafka.send(o.topic(), o.key(), o.payload()))
                                                .then(sh.db().sql("UPDATE outbox SET published = true WHERE id = :id")
                                                        .bind("id", o.id()).fetch().rowsUpdated()))
                                        .count())
                        .block(Duration.ofSeconds(10));
                if (sent != null && sent > 0) log.debug("shard {}: отправлено событий: {}", sh.id(), sent);
            } catch (Exception e) {
                log.warn("shard {}: relay не удался, повтор на следующем тике: {}", sh.id(), e.toString());
            }
        }
    }
}
