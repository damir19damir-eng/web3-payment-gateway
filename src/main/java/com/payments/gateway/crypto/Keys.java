package com.payments.gateway.crypto;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/** Ed25519 (подписи, долгоживущие ключи) и X25519 (эфемерные ключи сессий); публичные ключи — 32 «сырых» байта. */
public final class Keys {
    private Keys() {}

    private static final byte[] ED_PREFIX = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
    private static final byte[] X_PREFIX = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};

    public static KeyPair ed25519() { return gen("Ed25519"); }

    public static KeyPair x25519() { return gen("X25519"); }

    private static KeyPair gen(String alg) {
        try {
            return KeyPairGenerator.getInstance(alg).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] raw(PublicKey key) {
        byte[] e = key.getEncoded();
        return Arrays.copyOfRange(e, e.length - 32, e.length);
    }

    public static PublicKey ed25519Public(byte[] raw) throws GeneralSecurityException {
        return decode("Ed25519", ED_PREFIX, raw);
    }

    public static PublicKey x25519Public(byte[] raw) throws GeneralSecurityException {
        return decode("X25519", X_PREFIX, raw);
    }

    private static PublicKey decode(String alg, byte[] prefix, byte[] raw) throws GeneralSecurityException {
        if (raw == null || raw.length != 32) throw new GeneralSecurityException("public key must be 32 bytes");
        byte[] der = Arrays.copyOf(prefix, prefix.length + 32);
        System.arraycopy(raw, 0, der, prefix.length, 32);
        return KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(der));
    }

    public static byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    public static boolean verify(PublicKey key, byte[] data, byte[] sig) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update(data);
            return s.verify(sig);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String hex(byte[] b) { return HexFormat.of().formatHex(b); }

    public static String fingerprint(PublicKey key) { return hex(sha256(raw(key))).substring(0, 32); }
}
