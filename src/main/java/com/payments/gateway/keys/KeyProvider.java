package com.payments.gateway.keys;

import java.util.concurrent.CompletionStage;

/**
 * Долгоживущий ключ подписи сервера (Ed25519). Приватный ключ не покидает хранилище:
 * в проде подпись делает HashiCorp Vault (transit), у нас в памяти его нет.
 */
public interface KeyProvider {
    CompletionStage<byte[]> sign(byte[] data);

    /** 32 «сырых» байта публичного ключа — его клиенты закрепляют (pinning). */
    byte[] publicKeyRaw();
}
