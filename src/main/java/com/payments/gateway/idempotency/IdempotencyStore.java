package com.payments.gateway.idempotency;

import java.time.Duration;
import java.util.concurrent.CompletionStage;

/**
 * Idempotency Key + распределённая блокировка в одном флаконе.
 *
 *  begin()    — атомарно: ключа нет → ACQUIRED (запись-«замок» с токеном и TTL);
 *               запись есть и платёж ещё идёт → IN_PROGRESS;
 *               платёж завершён → DONE (+ сохранённый ответ, его отдаём повторно);
 *               тот же ключ, но другое тело запроса → CONFLICT.
 *  complete() — сохранить ответ (только владельцу замка: токен должен совпасть).
 *  abort()    — снять замок после ошибки, чтобы клиент мог повторить.
 */
public interface IdempotencyStore {
    enum Status { ACQUIRED, IN_PROGRESS, DONE, CONFLICT }

    record Begin(Status status, String token, String response) {}

    CompletionStage<Begin> begin(String key, String fingerprint, Duration lockTtl);

    CompletionStage<Boolean> complete(String key, String token, String response, Duration retention);

    CompletionStage<Boolean> abort(String key, String token);
}
