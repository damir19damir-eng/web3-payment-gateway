package com.payments.gateway.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Защищённый канал одной платёжной сессии.
 *
 * Для каждого направления (client→server, server→client) есть своя цепочка ключей:
 *   messageMaterial = HMAC(chainKey, 0x01),  nextChainKey = HMAC(chainKey, 0x02).
 * Ключ AES-256 и IV каждого сообщения выводятся из messageMaterial через HKDF и используются ровно один раз.
 * Старый chainKey затирается — украденное состояние не раскрывает прошлые сообщения (forward secrecy).
 * В AAD входят: id сессии, направление, номер сообщения и контекст (Idempotency-Key) — подмена любого из них
 * ломает тег GCM. Повтор (replay) отсекается по монотонному номеру сообщения.
 */
public final class SecureSession {
    public enum Role { CLIENT, SERVER }

    public static final class ReplayException extends GeneralSecurityException {
        private static final long serialVersionUID = 1L;
        ReplayException(String m) { super(m); }
    }

    public record Sealed(long seq, byte[] ct) {}

    /** Сколько номеров можно «перепрыгнуть» (клиент мог отправить сообщение, которое до нас не дошло). */
    public static final int MAX_SKIP = 256;

    private record Step(byte[] key, byte[] iv, byte[] next) {}

    private final String sid;
    private final String clientId;
    private final Role role;
    private final long createdAtMs;
    private byte[] sendCk;
    private byte[] recvCk;
    private long sendSeq;
    private long recvNext;
    private long messages;

    public SecureSession(String sid, String clientId, Role role, byte[] c2sChain, byte[] s2cChain, long nowMs) {
        this.sid = sid;
        this.clientId = clientId;
        this.role = role;
        this.createdAtMs = nowMs;
        this.sendCk = role == Role.CLIENT ? c2sChain : s2cChain;
        this.recvCk = role == Role.CLIENT ? s2cChain : c2sChain;
    }

    public String sid() { return sid; }

    public String clientId() { return clientId; }

    public long createdAtMs() { return createdAtMs; }

    public synchronized long messages() { return messages; }

    public synchronized Sealed seal(byte[] plain, String ctx) throws GeneralSecurityException {
        Step st = step(sendCk);
        long seq = sendSeq;
        byte[] ct = crypt(Cipher.ENCRYPT_MODE, st, aad(role == Role.CLIENT ? "c2s" : "s2c", seq, ctx), plain);
        Arrays.fill(sendCk, (byte) 0);
        sendCk = st.next();
        sendSeq++;
        messages++;
        return new Sealed(seq, ct);
    }

    /** Состояние меняется только после успешной проверки тега: мусор от атакующего сессию не «сдвигает». */
    public synchronized byte[] open(long seq, byte[] ct, String ctx) throws GeneralSecurityException {
        if (seq < recvNext) throw new ReplayException("message " + seq + " already consumed");
        if (seq - recvNext > MAX_SKIP) throw new GeneralSecurityException("message number too far ahead");
        byte[] ck = recvCk;
        for (long i = recvNext; i < seq; i++) ck = Hkdf.hmac(ck, new byte[]{2});
        Step st = step(ck);
        byte[] plain = crypt(Cipher.DECRYPT_MODE, st, aad(role == Role.CLIENT ? "s2c" : "c2s", seq, ctx), ct);
        recvCk = st.next();
        recvNext = seq + 1;
        messages++;
        return plain;
    }

    private static Step step(byte[] ck) {
        byte[] material = Hkdf.hmac(ck, new byte[]{1});
        byte[] next = Hkdf.hmac(ck, new byte[]{2});
        byte[] okm = Hkdf.derive(material, new byte[0], "pay-msg".getBytes(StandardCharsets.UTF_8), 44);
        return new Step(Arrays.copyOfRange(okm, 0, 32), Arrays.copyOfRange(okm, 32, 44), next);
    }

    private String aad(String dir, long seq, String ctx) {
        return "PAYv1|" + sid + "|" + dir + "|" + seq + "|" + ctx;
    }

    private static byte[] crypt(int mode, Step st, String aad, byte[] in) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, new SecretKeySpec(st.key(), "AES"), new GCMParameterSpec(128, st.iv()));
        c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        return c.doFinal(in);
    }
}
