package com.payments.gateway.config;

import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.transaction.reactive.TransactionalOperator;

import java.util.List;

/** Набор шардов Postgres: у каждого свой пул соединений и свой менеджер транзакций. */
public final class Shards {
    public record Shard(int id, DatabaseClient db, TransactionalOperator tx) {}

    private final List<Shard> shards;

    public Shards(List<Shard> shards) { this.shards = List.copyOf(shards); }

    public Shard get(int id) { return shards.get(id); }

    public List<Shard> all() { return shards; }
}
