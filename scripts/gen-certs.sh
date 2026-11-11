#!/usr/bin/env bash
# Dev-центр сертификации + сертификаты шлюза и клиента (для mTLS). Пароль всех хранилищ: changeit
set -euo pipefail
mkdir -p certs && cd certs
openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt -subj "/CN=Payments Dev CA" -days 365
for n in gateway client; do
  openssl req -newkey rsa:2048 -nodes -keyout $n.key -out $n.csr -subj "/CN=$n"
  printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth" > $n.ext
  openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $n.crt -days 365 -extfile $n.ext
  openssl pkcs12 -export -in $n.crt -inkey $n.key -certfile ca.crt -name $n -out $n.p12 -passout pass:changeit
done
keytool -importcert -noprompt -alias ca -file ca.crt -keystore ca.p12 -storetype PKCS12 -storepass changeit
echo "Готово: certs/gateway.p12, certs/client.p12, certs/ca.p12"
