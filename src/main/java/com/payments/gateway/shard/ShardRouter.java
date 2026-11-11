package com.payments.gateway.shard;

import com.payments.gateway.crypto.Keys;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;

/**
 * Консистентное хеширование (кольцо с виртуальными узлами): счёт → шард.
 * При добавлении шарда переезжает только ~1/N ключей, остальные остаются на месте.
 */
public final class ShardRouter {
    private final NavigableMap<Long, Integer> ring = new TreeMap<>();
    private final int shardCount;

    public ShardRouter(int shardCount, int virtualNodes) {
        if (shardCount < 1) throw new IllegalArgumentException("shardCount < 1");
        this.shardCount = shardCount;
        for (int s = 0; s < shardCount; s++)
            for (int v = 0; v < virtualNodes; v++) ring.put(hash("shard-" + s + "#" + v), s);
    }

    public int shardCount() { return shardCount; }

    public int shardFor(String accountId) {
        Map.Entry<Long, Integer> e = ring.ceilingEntry(hash(accountId));
        return (e != null ? e : ring.firstEntry()).getValue();
    }

    private static long hash(String s) {
        return ByteBuffer.wrap(Keys.sha256(s.getBytes(StandardCharsets.UTF_8))).getLong();
    }
}
