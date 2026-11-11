package com.payments.gateway.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** HKDF (RFC 5869) на HMAC-SHA256. */
public final class Hkdf {
    private Hkdf() {}

    public static byte[] hmac(byte[] key, byte[]... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[32] : key, "HmacSHA256"));
            for (byte[] p : parts) mac.update(p);
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) {
        byte[] prk = hmac(salt, ikm);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] t = new byte[0];
        for (int i = 1; out.size() < length; i++) {
            t = hmac(prk, t, info, new byte[]{(byte) i});
            out.writeBytes(t);
        }
        return Arrays.copyOf(out.toByteArray(), length);
    }
}
