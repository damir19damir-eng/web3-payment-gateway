package com.payments.gateway.crypto;

import javax.crypto.KeyAgreement;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Аутентифицированный обмен ключами (1 RTT) на каждую платёжную сессию:
 *   клиент:  эфемерный X25519 + подпись Ed25519 своим долгоживущим ключом (+ метка времени)
 *   сервер:  проверяет подпись, делает свой эфемерный X25519, подписывает транскрипт (ключом из Vault)
 * Секрет = ECDH(эфемерные ключи). Эфемерные приватные ключи не сохраняются, поэтому компрометация
 * долгоживущих ключей не раскрывает прошлые сессии (Perfect Forward Secrecy).
 */
public final class Handshake {
    private Handshake() {}

    public static final long MAX_SKEW_SECONDS = 60;
    private static final byte[] TAG_C = "PAYHS1-C".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TAG_S = "PAYHS1-S".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();

    public record ClientHello(String clientId, byte[] eph, long ts, byte[] sig) {}

    public record ServerHello(String sid, byte[] eph, byte[] sig) {}

    /** Результат на стороне сервера; transcript нужно подписать (KeyProvider/Vault) и вернуть клиенту. */
    public record Accepted(SecureSession session, byte[] serverEph, byte[] transcript) {}

    public static final class Client {
        private final String clientId;
        private final PrivateKey identityKey;
        private final PublicKey pinnedServerKey;
        private KeyPair eph;

        public Client(String clientId, PrivateKey identityKey, PublicKey pinnedServerKey) {
            this.clientId = clientId;
            this.identityKey = identityKey;
            this.pinnedServerKey = pinnedServerKey;
        }

        public ClientHello hello(long nowEpochSeconds) throws GeneralSecurityException {
            eph = Keys.x25519();
            byte[] pub = Keys.raw(eph.getPublic());
            byte[] sig = Keys.sign(identityKey, clientSigned(clientId, pub, nowEpochSeconds));
            return new ClientHello(clientId, pub, nowEpochSeconds, sig);
        }

        public SecureSession finish(ServerHello sh, long nowMs) throws GeneralSecurityException {
            if (eph == null) throw new GeneralSecurityException("hello() was not called");
            byte[] transcript = transcript(clientId, sh.sid(), Keys.raw(eph.getPublic()), sh.eph());
            if (!Keys.verify(pinnedServerKey, transcript, sh.sig()))
                throw new GeneralSecurityException("server signature invalid (wrong server key or MITM)");
            byte[][] k = deriveKeys(eph.getPrivate(), sh.eph(), transcript);
            eph = null; // эфемерный приватный ключ больше не нужен
            return new SecureSession(sh.sid(), clientId, SecureSession.Role.CLIENT, k[0], k[1], nowMs);
        }
    }

    public static Accepted accept(ClientHello h, PublicKey clientIdentity, long nowEpochSeconds, long nowMs)
            throws GeneralSecurityException {
        if (Math.abs(nowEpochSeconds - h.ts()) > MAX_SKEW_SECONDS)
            throw new GeneralSecurityException("hello timestamp out of range");
        if (!Keys.verify(clientIdentity, clientSigned(h.clientId(), h.eph(), h.ts()), h.sig()))
            throw new GeneralSecurityException("client signature invalid");
        KeyPair eph = Keys.x25519();
        byte[] serverEph = Keys.raw(eph.getPublic());
        byte[] sidBytes = new byte[16];
        RANDOM.nextBytes(sidBytes);
        String sid = HexFormat.of().formatHex(sidBytes);
        byte[] transcript = transcript(h.clientId(), sid, h.eph(), serverEph);
        byte[][] k = deriveKeys(eph.getPrivate(), h.eph(), transcript);
        SecureSession s = new SecureSession(sid, h.clientId(), SecureSession.Role.SERVER, k[0], k[1], nowMs);
        return new Accepted(s, serverEph, transcript);
    }

    private static byte[][] deriveKeys(PrivateKey mine, byte[] theirRaw, byte[] transcript)
            throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(mine);
        ka.doPhase(Keys.x25519Public(theirRaw), true);
        byte[] shared = ka.generateSecret();
        byte[] okm = Hkdf.derive(shared, Keys.sha256(transcript),
                "pay-e2ee-v1/keys".getBytes(StandardCharsets.UTF_8), 64);
        Arrays.fill(shared, (byte) 0);
        return new byte[][]{Arrays.copyOfRange(okm, 0, 32), Arrays.copyOfRange(okm, 32, 64)};
    }

    private static byte[] clientSigned(String clientId, byte[] eph, long ts) {
        return lp(TAG_C, clientId.getBytes(StandardCharsets.UTF_8), eph, Long.toString(ts).getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] transcript(String clientId, String sid, byte[] clientEph, byte[] serverEph) {
        return lp(TAG_S, clientId.getBytes(StandardCharsets.UTF_8), sid.getBytes(StandardCharsets.UTF_8), clientEph, serverEph);
    }

    /** Конкатенация с префиксами длины — исключает неоднозначность границ полей. */
    private static byte[] lp(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(ByteBuffer.allocate(4).putInt(p.length).array());
            out.writeBytes(p);
        }
        return out.toByteArray();
    }
}
