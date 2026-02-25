#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR="${1:-./certs}"

BAD_KEY="${CERTS_DIR}/bad_client.key"
BAD_CRT="${CERTS_DIR}/bad_client.crt"

BAD_CA_KEY="${CERTS_DIR}/bad_ca.key"
BAD_CA_CRT="${CERTS_DIR}/bad_ca.crt"

BAD_EXPIRED_CRT="${CERTS_DIR}/bad_client_expired.crt"

say(){ echo "[make-bad-client] $*"; }

need_openssl(){
  command -v openssl >/dev/null 2>&1 || {
    echo "ERROR: openssl not found in PATH" >&2
    exit 1
  }
}

mkdir -p "$CERTS_DIR"
need_openssl

say "Цель: создать 'плохой' клиентский сертификат, который НЕ доверен вашему основному CA (ca.crt)."
say "      Это удобно для теста mTLS: 'клиент прислал cert, но proxy/сервер не доверяет'."
echo

# ------------------------------------------------------------------------------
# 1) Создаём "плохой" CA (самоподписанный)
# ------------------------------------------------------------------------------
say "Шаг 1/3: генерируем 'плохой' CA (bad_ca.key + bad_ca.crt)"
openssl genrsa -out "$BAD_CA_KEY" 2048 >/dev/null 2>&1

openssl req -x509 -new -nodes \
  -key "$BAD_CA_KEY" \
  -sha256 \
  -days 3650 \
  -subj "/C=NL/O=Bad Test CA/CN=Bad Test CA" \
  -out "$BAD_CA_CRT" >/dev/null 2>&1

say "OK: $BAD_CA_KEY"
say "OK: $BAD_CA_CRT"
echo

# ------------------------------------------------------------------------------
# 2) Генерируем bad_client.key + CSR
# ------------------------------------------------------------------------------
say "Шаг 2/3: генерируем bad_client.key и CSR"
openssl genrsa -out "$BAD_KEY" 2048 >/dev/null 2>&1

CSR_TMP="$(mktemp)"
trap 'rm -f "$CSR_TMP" "${CSR_TMP}.srl" "${CERTS_DIR}/bad_client.cnf" "${CERTS_DIR}/bad_client_ext.cnf"' EXIT

openssl req -new \
  -key "$BAD_KEY" \
  -subj "/C=NL/O=Bad Client/CN=bad-client" \
  -out "$CSR_TMP" >/dev/null 2>&1

say "OK: $BAD_KEY"
echo

# ------------------------------------------------------------------------------
# 3) Подписываем CSR "плохим" CA, чтобы proxy (доверяющий ca.crt) НЕ принял cert
# ------------------------------------------------------------------------------
say "Шаг 3/3: подписываем bad_client.crt с помощью bad_ca (=> untrusted CA для вашего proxy)"

EXT_TMP="${CERTS_DIR}/bad_client_ext.cnf"
cat >"$EXT_TMP" <<'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl x509 -req \
  -in "$CSR_TMP" \
  -CA "$BAD_CA_CRT" \
  -CAkey "$BAD_CA_KEY" \
  -CAcreateserial \
  -out "$BAD_CRT" \
  -days 365 \
  -sha256 \
  -extfile "$EXT_TMP" >/dev/null 2>&1

say "OK: $BAD_CRT"
echo

# ------------------------------------------------------------------------------
# 4) (Опционально) Пробуем создать "просроченный" сертификат.
#    Это не всегда поддерживается одинаково разными версиями OpenSSL.
# ------------------------------------------------------------------------------
say "Опционально: пробуем создать $BAD_EXPIRED_CRT (просроченный cert)"
set +e
openssl x509 -req \
  -in "$CSR_TMP" \
  -CA "$BAD_CA_CRT" \
  -CAkey "$BAD_CA_KEY" \
  -CAcreateserial \
  -out "$BAD_EXPIRED_CRT" \
  -days 0 \
  -sha256 \
  -extfile "$EXT_TMP" >/dev/null 2>&1
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
  say "OK: $BAD_EXPIRED_CRT (days=0; обычно это 'expires now' — удобно для негативного теста)"
else
  say "SKIP: не удалось сделать expired cert (openssl версия/опции могут отличаться)."
  say "      Это не критично: bad_client.crt уже достаточно для теста 'untrusted CA'."
fi

echo
say "Готово."
say "Файлы для теста:"
say "  - $BAD_KEY"
say "  - $BAD_CRT"
say "Пояснение: bad_client.crt подписан bad_ca, а proxy доверяет вашему ca.crt => рукопожатие mTLS должно упасть (unknown CA / verify failed)."
