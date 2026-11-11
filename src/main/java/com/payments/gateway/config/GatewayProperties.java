package com.payments.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.util.List;

@ConfigurationProperties(prefix = "gateway")
public record GatewayProperties(
        List<Shard> shards,
        Vault vault,
        Crypto crypto,
        Clients clients,
        Long sessionTtlSeconds,
        Long maxMessagesPerSession
) {
    public record Shard(
            String url,
            String username,
            String password
    ) {}

    public record Vault(
            String addr,
            String token,
            String keyName
    ) {}

    public record Crypto(
            // Поля для криптографии, если требуются
    ) {}

    public record Clients(
            java.util.Map<String, String> keys
    ) {}
}