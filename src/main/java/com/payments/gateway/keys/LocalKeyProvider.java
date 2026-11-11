package com.payments.gateway.keys;

import com.payments.gateway.crypto.Keys;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/** Только для разработки и тестов: ключ в памяти процесса. */
public final class LocalKeyProvider implements KeyProvider {
    private final KeyPair pair = Keys.ed25519();

    @Override
    public CompletionStage<byte[]> sign(byte[] data) {
        try {
            return CompletableFuture.completedFuture(Keys.sign(pair.getPrivate(), data));
        } catch (GeneralSecurityException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    @Override
    public byte[] publicKeyRaw() { return Keys.raw(pair.getPublic()); }
}
