package com.payments.gateway.keys;

import org.springframework.web.reactive.function.client.WebClient;

import java.util.Base64;
import java.util.Map;
import java.util.concurrent.CompletionStage;

/**
 * Подпись через HashiCorp Vault Transit (ключ типа ed25519): приватный ключ не покидает Vault.
 * Подготовка: vault secrets enable transit && vault write transit/keys/gateway-signing type=ed25519
 * В проде вместо статического токена используйте AppRole / Kubernetes auth и TLS (mTLS) до Vault.
 */
@SuppressWarnings("unchecked")
public final class VaultKeyProvider implements KeyProvider {
    private final WebClient vault;
    private final String keyName;
    private final byte[] publicKey;

    public VaultKeyProvider(String addr, String token, String keyName) {
        this.keyName = keyName;
        this.vault = WebClient.builder().baseUrl(addr).defaultHeader("X-Vault-Token", token).build();
        Map<String, Object> r = vault.get().uri("/v1/transit/keys/{k}", keyName)
                .retrieve().bodyToMono(Map.class).block();
        Map<String, Object> data = (Map<String, Object>) r.get("data");
        Map<String, Object> versions = (Map<String, Object>) data.get("keys");
        Map<String, Object> latest = (Map<String, Object>) versions.get(String.valueOf(data.get("latest_version")));
        this.publicKey = Base64.getDecoder().decode((String) latest.get("public_key"));
    }

    @Override
    public CompletionStage<byte[]> sign(byte[] data) {
        return vault.post().uri("/v1/transit/sign/{k}", keyName)
                .bodyValue(Map.of("input", Base64.getEncoder().encodeToString(data)))
                .retrieve().bodyToMono(Map.class)
                .map(r -> {
                    String sig = (String) ((Map<String, Object>) r.get("data")).get("signature"); // "vault:v1:<base64>"
                    return Base64.getDecoder().decode(sig.substring(sig.lastIndexOf(':') + 1));
                })
                .toFuture();
    }

    @Override
    public byte[] publicKeyRaw() { return publicKey; }
}
