package com.payments.gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.payments.gateway.crypto.Keys;
import com.payments.gateway.crypto.SessionRegistry;
import com.payments.gateway.fraud.AnomalyDetector;
import com.payments.gateway.idempotency.IdempotencyStore;
import com.payments.gateway.idempotency.RedisIdempotencyStore;
import com.payments.gateway.keys.KeyProvider;
import com.payments.gateway.keys.LocalKeyProvider;
import com.payments.gateway.keys.VaultKeyProvider;
import com.payments.gateway.shard.ShardRouter;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.transaction.reactive.TransactionalOperator;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class GatewayConfig {
    private static final Logger log = LoggerFactory.getLogger(GatewayConfig.class);

    @Bean
    Shards shards(GatewayProperties p) {
        List<Shards.Shard> list = new ArrayList<>();
        for (int i = 0; i < p.shards().size(); i++) {
            GatewayProperties.Shard s = p.shards().get(i);
            ConnectionFactoryOptions opts = ConnectionFactoryOptions.parse(s.url()).mutate()
                    .option(ConnectionFactoryOptions.USER, s.username())
                    .option(ConnectionFactoryOptions.PASSWORD, s.password())
                    .build();
            ConnectionFactory cf = ConnectionFactories.get(opts);
            list.add(new Shards.Shard(i, DatabaseClient.create(cf),
                    TransactionalOperator.create(new R2dbcTransactionManager(cf))));
        }
        return new Shards(list);
    }

    @Bean
    ShardRouter shardRouter(GatewayProperties p) { return new ShardRouter(p.shards().size(), 128); }

    @Bean
    KeyProvider keyProvider(GatewayProperties p) {
        GatewayProperties.Vault v = p.vault();
        KeyProvider kp = (v != null && v.addr() != null && !v.addr().isBlank())
                ? new VaultKeyProvider(v.addr(), v.token(), v.keyName())
                : new LocalKeyProvider();
        if (kp instanceof LocalKeyProvider) log.warn("Vault не настроен: используется ЛОКАЛЬНЫЙ ключ подписи (только для разработки)");
        // этот ключ клиенты закрепляют (SERVER_PUB)
        log.info("Публичный ключ сервера (Ed25519, Base64): {}", Base64.getEncoder().encodeToString(kp.publicKeyRaw()));
        return kp;
    }

    @Bean
    IdempotencyStore idempotencyStore(ReactiveStringRedisTemplate redis) { return new RedisIdempotencyStore(redis); }

    @Bean
    SessionRegistry sessionRegistry(GatewayProperties p) {
        GatewayProperties.Crypto c = p.crypto();
        long ttl = p.sessionTtlSeconds() != null ? p.sessionTtlSeconds() : 900;
        long max = p.maxMessagesPerSession() != null ? p.maxMessagesPerSession() : 1000;
        return new SessionRegistry(ttl * 1000, max);
    }

    @Bean
    ClientDirectory clientDirectory(GatewayProperties p) throws GeneralSecurityException {
        Map<String, PublicKey> keys = new HashMap<>();
        if (p.clients() != null && p.clients().keys() != null) {
            for (var e : p.clients().keys().entrySet()) {
                keys.put(e.getKey(), Keys.ed25519Public(Base64.getDecoder().decode(e.getValue())));
            }
        }
        return new ClientDirectory(keys);
    }

    @Bean
    AnomalyDetector anomalyDetector(KafkaTemplate<String, String> kafka, ObjectMapper mapper) {
        return new AnomalyDetector(AnomalyDetector.Config.defaults(), System::currentTimeMillis, alert -> {
            try {
                kafka.send("fraud.alerts", alert.clientId(), mapper.writeValueAsString(alert));
            } catch (Exception e) {
                log.error("Не удалось отправить fraud-alert: {}", alert, e);
            }
        });
    }
}
