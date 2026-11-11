package com.payments.gateway.client;

import com.payments.gateway.crypto.Handshake;
import com.payments.gateway.crypto.Keys;
import com.payments.gateway.crypto.SecureSession;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Пример клиента: handshake -> зашифрованный платёж -> повтор с тем же Idempotency-Key.
 * Переменные окружения: GATEWAY_URL, CLIENT_ID, CLIENT_KEY_PKCS8, SERVER_PUB.
 * Без CLIENT_KEY_PKCS8 печатает новую пару ключей. Для mTLS запускайте с -Djavax.net.ssl.keyStore=... (см. README).
 */
public final class DemoClient {
    public static void main(String[] args) throws Exception {
        String url = env("GATEWAY_URL", "https://localhost:8443");
        String id = env("CLIENT_ID", "acme");
        String keyB64 = System.getenv("CLIENT_KEY_PKCS8");
        if (keyB64 == null) {
            KeyPair kp = Keys.ed25519();
            System.out.println("export CLIENT_KEY_PKCS8=" + b64(kp.getPrivate().getEncoded()));
            System.out.println("# добавьте в application.yml:  gateway.clients." + id + ": \"" + b64(Keys.raw(kp.getPublic())) + "\"");
            return;
        }
        PrivateKey priv = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(dec(keyB64)));
        var serverKey = Keys.ed25519Public(dec(env("SERVER_PUB", "")));
        HttpClient http = HttpClient.newHttpClient();

        Handshake.Client hs = new Handshake.Client(id, priv, serverKey);
        var hello = hs.hello(Instant.now().getEpochSecond());
        String r = post(http, url + "/v1/handshake", json("clientId", id, "eph", b64(hello.eph()),
                "ts", Long.toString(hello.ts()), "sig", b64(hello.sig())), null);
        SecureSession s = hs.finish(new Handshake.ServerHello(field(r, "sid"), dec(field(r, "eph")), dec(field(r, "sig"))),
                System.currentTimeMillis());
        System.out.println("Сессия установлена: " + s.sid());

        String idem = UUID.randomUUID().toString();
        byte[] payment = "{\"from\":\"acc-A\",\"to\":\"acc-B\",\"amountMinor\":1500,\"currency\":\"USD\"}".getBytes();
        for (int attempt = 1; attempt <= 2; attempt++) { // вторая попытка = повтор после «сбоя сети»
            var sealed = s.seal(payment, idem);
            String resp = post(http, url + "/v1/payments",
                    json("sid", s.sid(), "seq", Long.toString(sealed.seq()), "ct", b64(sealed.ct())), idem);
            byte[] plain = s.open(Long.parseLong(field(resp, "seq")), dec(field(resp, "ct")), idem);
            System.out.println("Попытка " + attempt + ": " + new String(plain));
        }
    }

    private static String post(HttpClient http, String url, String body, String idem) throws Exception {
        HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        if (idem != null) rb.header("Idempotency-Key", idem);
        HttpResponse<String> resp = http.send(rb.build(), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) throw new IllegalStateException("HTTP " + resp.statusCode() + ": " + resp.body());
        return resp.body();
    }

    private static String json(String... kv) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) sb.append(i > 0 ? "," : "").append('"').append(kv[i]).append("\":\"").append(kv[i + 1]).append('"');
        return sb.append('}').toString();
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        if (!m.find()) throw new IllegalStateException("нет поля " + name + " в " + json);
        return m.group(1);
    }

    private static String env(String k, String def) { String v = System.getenv(k); return v == null ? def : v; }

    private static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    private static byte[] dec(String s) { return Base64.getDecoder().decode(s); }
}
