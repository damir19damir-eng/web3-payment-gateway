package com.payments.gateway.config;

import java.security.PublicKey;
import java.util.Map;

/** Реестр публичных ключей клиентов (Ed25519). В проде — таблица в БД или Vault KV, с ротацией. */
public record ClientDirectory(Map<String, PublicKey> keys) {
    public PublicKey get(String clientId) { return keys.get(clientId); }
}
