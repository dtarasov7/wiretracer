#!/usr/bin/env bash
set -euo pipefail

# make_bad_client_eku.sh
#
# Делает "плохой" клиентский сертификат с НЕПРАВИЛЬНЫМ EKU:
#   - вместо extendedKeyUsage=clientAuth ставим serverAuth (или вообще убираем clientAuth).
#
# ВАЖНО:
#  - Чтобы проверить именно EKU-ошибку, прокси/сервер должны ДОВЕРЯТЬ CA, который подписал cert.
#    Поэтому этот скрипт подписывает bad_client_eku.crt ВАШИМ нормальным CA.
#  - Нужны файлы CA: ./certs/ca.crt и ./certs/ca.key (ключ CA нужен для подписи).
#
# Результат:
#   ./certs/bad_client_eku.crt
#   ./certs/bad_client_eku.key

CERTS_DIR="${1:-./certs}"

CA_CRT="${CERTS_DIR}/ca.crt"
CA_KEY="${CERTS_DIR}/ca.key"   # <-- нужен!
OUT_KEY="${CERTS_DIR}/bad_client_eku.key"
OUT_CRT="${CERTS_DIR}/bad_client_eku.crt"

say(){ echo "[make-bad-client-eku] $*"; }

need_openssl(){
  command -v openssl >/dev/null 2>&1 || {
    echo "ERROR: openssl not found in PATH" >&2
    exit 1
  }
}

need_file(){
  local p="$1"
  [[ -f "$p" ]] || {
    echo "ERROR: required file not found: $p" >&2
    exit 1
  }
}

need_openssl
mkdir -p "$CERTS_DIR"
need_file "$CA_CRT"
need_file "$CA_KEY"

say "Цель: сделать client cert, который формально доверен CA, но имеет НЕПРАВИЛЬНЫЙ EKU."
say "      Типичный диагноз: 'unsuitable certificate purpose' / 'unsupported certificate purpose'."
echo

# 1) key
say "Шаг 1/3: генерируем ключ клиента: $OUT_KEY"
openssl genrsa -out "$OUT_KEY" 2048 >/dev/null 2>&1

# 2) csr
say "Шаг 2/3: создаём CSR"
CSR_TMP="$(mktemp)"
trap 'rm -f "$CSR_TMP" "${CSR_TMP}.srl" "${CERTS_DIR}/bad_client_eku_ext.cnf"' EXIT

openssl req -new \
  -key "$OUT_KEY" \
  -subj "/C=NL/O=Bad EKU Client/CN=bad-client-eku" \
  -out "$CSR_TMP" >/dev/null 2>&1

# 3) sign with WRONG EKU
say "Шаг 3/3: подписываем CSR вашим CA, но с EKU=serverAuth (НЕ clientAuth)"
EXT_TMP="${CERTS_DIR}/bad_client_eku_ext.cnf"
cat >"$EXT_TMP" <<'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
# ВОТ ЗДЕСЬ "ПЛОХО": клиентский сертификат должен иметь clientAuth,
# а мы специально выдаём serverAuth, чтобы mTLS проверка упала.
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl x509 -req \
  -in "$CSR_TMP" \
  -CA "$CA_CRT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -out "$OUT_CRT" \
  -days 365 \
  -sha256 \
  -extfile "$EXT_TMP" >/dev/null 2>&1

say "OK: $OUT_CRT"
echo
say "Готово."
say "Файлы:"
say "  - $OUT_KEY"
say "  - $OUT_CRT"
say "Пояснение: сертификат доверен вашему CA, но имеет EKU=serverAuth => корректная проверка client cert должна его отклонить."
