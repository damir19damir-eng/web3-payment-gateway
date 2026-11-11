-- KEYS[1]: ключ счетчика в Redis (например, "rate:limit:acc-A")
-- ARGV[1]: лимит запросов (например, 10)
-- ARGV[2]: TTL (время жизни ключа в секундах, например, 60)

local current = redis.call('get', KEYS[1])
if current and tonumber(current) >= tonumber(ARGV[1]) then
    return 0 -- Лимит исчерпан
end

current = redis.call('incr', KEYS[1])
if tonumber(current) == 1 then
    redis.call('expire', KEYS[1], ARGV[2])
end

return 1 -- Успешно, запрос разрешен