-- Выполняется на КАЖДОМ шарде.
CREATE TABLE IF NOT EXISTS accounts (
    id       text PRIMARY KEY,
    currency text   NOT NULL CHECK (length(currency) = 3),
    balance  bigint NOT NULL CHECK (balance >= 0)          -- минорные единицы; отрицательный баланс невозможен
);

CREATE TABLE IF NOT EXISTS payments (
    id              uuid PRIMARY KEY,
    idempotency_key text   NOT NULL UNIQUE,                -- окончательная защита от двойного списания
    src             text   NOT NULL,
    dst             text   NOT NULL,
    amount          bigint NOT NULL CHECK (amount > 0),
    currency        text   NOT NULL,
    status          text   NOT NULL,                       -- PENDING / ACCEPTED / REJECTED
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Transactional Outbox: пишется в той же транзакции, что и списание
CREATE TABLE IF NOT EXISTS outbox (
    id         uuid PRIMARY KEY,
    topic      text NOT NULL,
    msg_key    text NOT NULL,
    payload    text NOT NULL,
    published  boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS outbox_pending ON outbox (created_at) WHERE NOT published;

-- Дедупликация потребителя (идемпотентное зачисление)
CREATE TABLE IF NOT EXISTS processed_events (
    event_id     uuid PRIMARY KEY,
    processed_at timestamptz NOT NULL DEFAULT now()
);

-- Аудит с хеш-цепочкой; используется на шарде 0
CREATE TABLE IF NOT EXISTS audit_log (
    id              bigserial PRIMARY KEY,
    topic           text   NOT NULL,
    kafka_partition int    NOT NULL,
    kafka_offset    bigint NOT NULL,
    payload         text   NOT NULL,
    prev_hash       text   NOT NULL,
    hash            text   NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (topic, kafka_partition, kafka_offset)
);
CREATE OR REPLACE FUNCTION forbid_audit_change() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$ LANGUAGE plpgsql;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION forbid_audit_change();
