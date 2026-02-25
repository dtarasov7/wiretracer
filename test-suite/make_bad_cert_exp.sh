#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR="${1:-./certs}"

#BAD_KEY="${CERTS_DIR}/bad_client.key"
#BAD_CRT="${CERTS_DIR}/bad_client.crt"

CA_KEY="${CERTS_DIR}/ca.key"
CA_CRT="${CERTS_DIR}/ca.crt"

CSR="${CERTS_DIR}/client.csr"

BAD_EXPIRED_CRT="${CERTS_DIR}/client_expired.crt"

say(){ echo "[make-bad-client] $*"; }

need_openssl(){
  command -v openssl >/dev/null 2>&1 || {
    echo "ERROR: openssl not found in PATH" >&2
    exit 1
  }
}

#mkdir -p "$CERTS_DIR"

need_openssl

say "Опционально: пробуем создать $BAD_EXPIRED_CRT (просроченный cert)"
set +e
openssl x509 -req \
  -in "$CSR" \
  -CA "$CA_CRT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -out "$BAD_EXPIRED_CRT" \
  -days 0 \
  -sha256 \
  - -extfile ./certs/client.ext >/dev/null 2>&1
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
  say "OK: $BAD_EXPIRED_CRT (days=0; обычно это 'expires now' — удобно для негативного теста)"
else
  say "SKIP: не удалось сделать expired cert (openssl версия/опции могут отличаться)."
  say "      Это не критично: bad_client.crt уже достаточно для теста 'untrusted CA'."
fi

