-- Демо-счета (суммы в центах). Вставлены на оба шарда; используется строка того шарда, куда маршрутизирует хеш.
INSERT INTO accounts(id, currency, balance) VALUES ('acc-A', 'USD', 1000000), ('acc-B', 'USD', 0)
ON CONFLICT DO NOTHING;
