#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# run_proxy_test_suite.sh
#
# Назначение:
#   Полный интеграционный прогон тестов диагностического MITM proxy:
#     - HTTP/1.1 (TLS)
#     - HTTP/2   (TLS)
#     - негативные сценарии (hang/close_early/truncate/rst/sleep_headers)
#     - клиентские негативные сценарии (client_close_early/client_rst/client_half_close)
#     - mTLS (client->proxy + proxy->upstream):
#         * OK (клиент предъявляет валидный cert, proxy требует cert)
#         * клиент НЕ прислал cert (ожидаемый handshake fail)
#         * клиент прислал "плохой" cert (ожидаемый handshake fail)
#         * upstream mTLS fail (клиент->proxy OK, но proxy->upstream ломается)
#
# Важная цель:
#   Даже если некоторые негативные тесты завершаются ошибкой на клиенте (EOF/reset/timeout),
#   suite должен:
#     - не падать из-за этого (это ожидаемо)
#     - НЕ засорять логи traceback'ами (используем --quiet-expected у fault_client)
#     - в конце запустить verify_headless.py и проверить JSONL-диагностику
#
# Опция:
#   --no-proxy  : не стартуем proxy (предполагаем что он уже запущен в TUI),
#                JSONL не трогаем, verify фильтрует записи по --since.
# ------------------------------------------------------------------------------

PY=python3
PROXY_BIN=../wiretracer.py
PROXY_CFG=../config.yaml

CLIENT=./fault_client.py
VERIFY=./verify_headless.py

HOST=127.0.0.1

# TLS listeners
PORT_H1=19100
PORT_H2=19101
PORT_GRPC_NATIVE=9101

# mTLS listeners (OK)
PORT_MTLS_H1=29100
PORT_MTLS_H2=29101

# mTLS listeners (upstream-fail)
PORT_MTLS_BADUP_H1=29200
PORT_MTLS_BADUP_H2=29201

CERTS=./certs
SNI=localhost

JSONL=./headless.jsonl
PROXY_LOG=./proxy_headless.log

STARTUP_TRIES=120   # 12s
KILL_GRACE_S=3

HANG_TIMEOUT="60s"

PROXY_PID=""

NO_PROXY=0
if [[ "${1:-}" == "--no-proxy" ]]; then
  NO_PROXY=1
  shift || true
fi

say(){ echo "[suite] $*"; }

banner() {
  echo
  echo "--------------------------------------------------------------------------------"
  echo "$*"
  echo "--------------------------------------------------------------------------------"
}

check_port_once() {
  local host="$1" port="$2"
  if command -v nc >/dev/null 2>&1; then
    nc -z "$host" "$port" >/dev/null 2>&1
    return $?
  fi
  (echo >/dev/tcp/"$host"/"$port") >/dev/null 2>&1
  return $?
}

wait_port() {
  local host="$1" port="$2" name="$3"
  say "ожидаем, что $name откроет порт $host:$port (эмулируем readiness proxy listener)"
  for _ in $(seq 1 "$STARTUP_TRIES"); do
    if check_port_once "$host" "$port"; then
      say "$name is up on $host:$port"
      return 0
    fi
    sleep 0.1
  done
  say "ERROR: $name did not open on $host:$port"
  return 1
}

run_cmd() {
  echo
  echo "==> $*"
  "$@"
}

# Негативные тесты: команда может завершиться rc!=0 — это ожидаемо.
# Важно: мы НЕ хотим чтобы suite падал.
run_allow_fail() {
  echo
  echo "==> $*"
  set +e
  "$@"
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    say "command rc=$rc (allowed/expected for negative test)"
  fi
  return 0
}

start_proxy() {
  : >"$PROXY_LOG"
  : >"$JSONL"
  say "starting proxy headless..."
  run_cmd "$PY" "$PROXY_BIN" --config "$PROXY_CFG" --headless >>"$PROXY_LOG" 2>&1 &
  PROXY_PID="$!"
  say "proxy pid=$PROXY_PID (log: $PROXY_LOG)"
}

stop_proxy() {
  if [[ -n "${PROXY_PID:-}" ]]; then
    say "stopping proxy pid=$PROXY_PID"
    kill -TERM "$PROXY_PID" >/dev/null 2>&1 || true
    for _ in $(seq 1 $((KILL_GRACE_S * 10))); do
      if ! kill -0 "$PROXY_PID" >/dev/null 2>&1; then
        PROXY_PID=""
        return 0
      fi
      sleep 0.1
    done
    say "proxy still alive -> SIGKILL"
    kill -KILL "$PROXY_PID" >/dev/null 2>&1 || true
    PROXY_PID=""
  fi
}

cleanup(){ [[ "$NO_PROXY" -eq 0 ]] && stop_proxy || true; }
trap cleanup EXIT

main() {
  local TID_BASE="tid$(date +%s)"
  local WITH_GRPC_NATIVE=0
  # IMPORTANT: start time for filtering jsonl when we do NOT own the file
  local SUITE_SINCE_EPOCH
  SUITE_SINCE_EPOCH="$(date +%s)"
  say "tid_base=$TID_BASE"

  if [[ "$NO_PROXY" -eq 0 ]]; then
    start_proxy
  else
    say "proxy is assumed to be already running (TUI mode); jsonl will NOT be truncated"
    say "since_epoch=$SUITE_SINCE_EPOCH (verify will ignore older records)"
  fi

  # --------------------------------------------------------------------------
  # Ждём порты. Здесь мы явно проговариваем: "какой listener и почему нам важен".
  # --------------------------------------------------------------------------
  wait_port "$HOST" "$PORT_H1" "proxy(tls/http1)"
  wait_port "$HOST" "$PORT_H2" "proxy(tls/h2)"
  wait_port "$HOST" "$PORT_MTLS_H1" "proxy(mtls/http1)"
  wait_port "$HOST" "$PORT_MTLS_H2" "proxy(mtls/h2)"
  wait_port "$HOST" "$PORT_MTLS_BADUP_H1" "proxy(mtls/http1 bad-upstream)"
  wait_port "$HOST" "$PORT_MTLS_BADUP_H2" "proxy(mtls/h2 bad-upstream)"
  if check_port_once "$HOST" "$PORT_GRPC_NATIVE"; then
    WITH_GRPC_NATIVE=1
    say "proxy(native grpc) is up on $HOST:$PORT_GRPC_NATIVE"
  else
    say "proxy(native grpc) listener $HOST:$PORT_GRPC_NATIVE not found; native grpc tests will be skipped"
  fi

  # ==========================================================================
  # 1) HAPPY PATHS (TLS)
  # ==========================================================================
  banner "[case] happy / http1 chat (TLS)\n[case] emulate: HTTP/1.1 keep-alive; 5 запросов по одному соединению; ожидаем 5 event со статусом 200"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode chat --cycles 5 --interval 1 --path "/mode/ok?tid=${TID_BASE}_h1_chat5"

  banner "[case] happy / h2 chat (TLS)\n[case] emulate: HTTP/2; 5 запросов; ожидаем 5 event со статусом 200"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode chat --cycles 5 --interval 1 --path "/mode/ok?tid=${TID_BASE}_h2_chat5"

  # ==========================================================================
  # 1.1) PROXY protocol tests (auto none/v1/v2 + malformed)
  # ==========================================================================
  banner "[case] proxy / none / http1\n[case] emulate: обычный TLS-клиент без PROXY header; ожидаем 200"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_proxy_none_h1&expect_proxy=none" \
    --proxy-header none

  banner "[case] proxy / v1 / http1\n[case] emulate: клиент отправляет PROXY v1 перед TLS; ожидаем 200 и client_ip из PROXY"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_proxy_v1_h1&expect_proxy=v1" \
    --proxy-header v1 \
    --proxy-src-ip 203.0.113.10 --proxy-dst-ip 192.0.2.10 --proxy-src-port 54321 --proxy-dst-port 443

  banner "[case] proxy / v2 / http1\n[case] emulate: клиент отправляет PROXY v2 перед TLS; ожидаем 200 и client_ip из PROXY"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_proxy_v2_h1&expect_proxy=v2" \
    --proxy-header v2 \
    --proxy-src-ip 198.51.100.20 --proxy-dst-ip 192.0.2.20 --proxy-src-port 42424 --proxy-dst-port 443

  banner "[case] proxy / malformed / http1 (expected fail)\n[case] emulate: клиент отправляет битый PROXY header перед TLS; ожидаем proxy_protocol_error"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_proxy_malformed_h1" \
    --proxy-header malformed

  banner "[case] proxy / none / h2\n[case] emulate: обычный TLS+h2 клиент без PROXY header; ожидаем 200"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_proxy_none_h2" \
    --proxy-header none

  banner "[case] proxy / v1 / h2\n[case] emulate: клиент отправляет PROXY v1 перед TLS+h2; ожидаем 200 и client_ip из PROXY"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_proxy_v1_h2" \
    --proxy-header v1 \
    --proxy-src-ip 203.0.113.10 --proxy-dst-ip 192.0.2.10 --proxy-src-port 54321 --proxy-dst-port 443

  banner "[case] proxy / v2 / h2\n[case] emulate: клиент отправляет PROXY v2 перед TLS+h2; ожидаем 200 и client_ip из PROXY"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_proxy_v2_h2" \
    --proxy-header v2 \
    --proxy-src-ip 198.51.100.20 --proxy-dst-ip 192.0.2.20 --proxy-src-port 42424 --proxy-dst-port 443

  # ==========================================================================
  # 1.2) gRPC tests (TLS/h2)
  # ==========================================================================
  banner "[case] happy / grpc chat (TLS)\n[case] emulate: gRPC over h2; 3 запроса; ожидаем event с protocol=grpc и статусами 200"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto grpc --mode chat --cycles 3 --interval 1 --path "/mode/ok?tid=${TID_BASE}_grpc_chat3"

  banner "[case] proxy / none / grpc\n[case] emulate: grpc client без PROXY header; ожидаем 200 и protocol=grpc"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto grpc --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_proxy_none_grpc&expect_proxy=none" \
    --proxy-header none

  banner "[case] proxy / v1 / grpc\n[case] emulate: grpc client отправляет PROXY v1 перед TLS+h2; ожидаем 200 и client_ip из PROXY"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto grpc --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_proxy_v1_grpc&expect_proxy=v1" \
    --proxy-header v1 \
    --proxy-src-ip 203.0.113.10 --proxy-dst-ip 192.0.2.10 --proxy-src-port 54321 --proxy-dst-port 443

  banner "[case] proxy / v2 / grpc\n[case] emulate: grpc client отправляет PROXY v2 перед TLS+h2; ожидаем 200 и client_ip из PROXY"
  run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto grpc --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_proxy_v2_grpc&expect_proxy=v2" \
    --proxy-header v2 \
    --proxy-src-ip 198.51.100.20 --proxy-dst-ip 192.0.2.20 --proxy-src-port 42424 --proxy-dst-port 443

  if [[ "$WITH_GRPC_NATIVE" -eq 1 ]]; then
    banner "[case] happy / grpc_native chat (TLS)\n[case] emulate: grpcio client к честному gRPC upstream через listener grpc-exporter; ожидаем 2 успешных вызова"
    run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_GRPC_NATIVE" --certs "$CERTS" --sni "$SNI" \
      --proto grpc_native --mode chat --cycles 2 --interval 1 \
      --path "/unused?tid=${TID_BASE}_grpc_native_chat2" \
      --proxy-header none

    banner "[case] grpc_native / client-cert\n[case] emulate: grpcio клиент предъявляет client cert при обращении к listener grpc-exporter"
    run_cmd "$PY" "$CLIENT" --proxy-host "$HOST" --proxy-port "$PORT_GRPC_NATIVE" --certs "$CERTS" --sni "$SNI" \
      --proto grpc_native --mode ok --cycles 1 --interval 0 \
      --path "/unused?tid=${TID_BASE}_grpc_native_client_cert_ok" \
      --proxy-header none \
      --client-cert "$CERTS/client.crt" --client-key "$CERTS/client.key"
  fi

  # ==========================================================================
  # 2) NEGATIVE SERVER-SIDE (TLS): hang/close_early/truncate/rst/sleep_headers
  # ==========================================================================
  banner "[case] negative / http1 hang (TLS)\n[case] emulate: server зависает и не отдаёт ответ; клиент может быть прибит timeout; ожидаем в JSONL conn(close) с *timeout* или ошибкой"
  if command -v timeout >/dev/null 2>&1; then
    run_allow_fail timeout "$HANG_TIMEOUT" "$PY" "$CLIENT" --quiet-expected \
      --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
      --proto http1 --mode ok --path "/mode/hang?t=999&tid=${TID_BASE}_neg_h1_hang"
  else
    run_allow_fail "$PY" "$CLIENT" --quiet-expected \
      --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
      --proto http1 --mode ok --path "/mode/hang?t=999&tid=${TID_BASE}_neg_h1_hang"
  fi

  banner "[case] negative / http1 close_early (TLS)\n[case] emulate: server принимает запрос и сразу закрывает соединение; клиент может получить EOF; ожидаем conn(close) с upstream_fin/upstream_rst или похожим"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --path "/mode/close_early?tid=${TID_BASE}_neg_h1_close_early"

  banner "[case] negative / http1 truncate (TLS)\n[case] emulate: server отдаёт частичный ответ/тело и закрывает; ожидаем event (возможно 200), и/или conn(close) с upstream_fin"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --path "/mode/truncate?tid=${TID_BASE}_neg_h1_truncate"

  banner "[case] negative / http1 rst (TLS)\n[case] emulate: server делает abort/RESET; клиент может получить reset/EOF; ожидаем conn(close) с upstream_rst"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --path "/mode/rst?tid=${TID_BASE}_neg_h1_rst"

  banner "[case] negative-ish / http1 sleep_headers (TLS)\n[case] emulate: server задерживает отправку заголовков (t=10); ожидаем, что запрос завершится, но будет длительный duration"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --path "/mode/sleep_headers?t=10&tid=${TID_BASE}_neg_h1_sleep_headers"

  banner "[case] negative / h2 hang (TLS)\n[case] emulate: аналогично http1 hang, но в HTTP/2; ожидаем conn(close) с timeout/idle_timeout или ошибкой"
  if command -v timeout >/dev/null 2>&1; then
    run_allow_fail timeout "$HANG_TIMEOUT" "$PY" "$CLIENT" --quiet-expected \
      --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
      --proto h2 --mode ok --path "/mode/hang?t=999&tid=${TID_BASE}_neg_h2_hang"
  else
    run_allow_fail "$PY" "$CLIENT" --quiet-expected \
      --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
      --proto h2 --mode ok --path "/mode/hang?t=999&tid=${TID_BASE}_neg_h2_hang"
  fi

  banner "[case] negative / h2 close_early (TLS)\n[case] emulate: server закрывает соединение до ответа в h2; ожидаем conn(close) и/или event с пустым телом"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode ok --path "/mode/close_early?tid=${TID_BASE}_neg_h2_close_early"

  banner "[case] negative / h2 truncate (TLS)\n[case] emulate: server отдаёт часть данных и закрывает; клиент может упасть по EOF; ожидаем conn(close) и/или event/error"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode ok --path "/mode/truncate?tid=${TID_BASE}_neg_h2_truncate"

  banner "[case] negative / h2 rst (TLS)\n[case] emulate: RST/abort; ожидание признаков reset на соединении"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode ok --path "/mode/rst?tid=${TID_BASE}_neg_h2_rst"

  # ==========================================================================
  # 3) NEGATIVE CLIENT-DRIVEN (TLS)
  # ==========================================================================
  banner "[case] negative / client_close_early (TLS)\n[case] emulate: клиент отправляет запрос и закрывает соединение, не читая ответ; ожидаем conn(close) с client_fin/close_early диагностикой"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode client_close_early --path "/mode/ok?tid=${TID_BASE}_neg_client_close_early"

  banner "[case] negative / client_rst (TLS)\n[case] emulate: клиент делает abort()/RST после запроса; ожидаем conn(close) с rst/reset диагностикой"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode client_rst --path "/mode/ok?tid=${TID_BASE}_neg_client_rst"

  banner "[case] negative / client_half_close (TLS)\n[case] emulate: клиент делает half-close (SHUT_WR), но читает ответ; ожидаем корректную обработку half-close"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode client_half_close --path "/mode/ok?tid=${TID_BASE}_neg_client_half_close"

  # ==========================================================================
  # 4) mTLS TESTS
  #    Важно: здесь TLS рукопожатие само по себе часть теста.
  # ==========================================================================
  banner "[case] mtls / http1 OK\n[case] emulate: proxy требует client cert (client->proxy mTLS), клиент предъявляет валидный cert; далее proxy ходит на upstream по mTLS своим cert; ожидаем 200"
  run_cmd "$PY" "$CLIENT" \
    --proxy-host "$HOST" --proxy-port "$PORT_MTLS_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_mtls_h1_ok" \
    --client-cert "$CERTS/client.crt" --client-key "$CERTS/client.key"

  banner "[case] mtls / h2 OK\n[case] emulate: то же, но HTTP/2; ожидаем 200"
  run_cmd "$PY" "$CLIENT" \
    --proxy-host "$HOST" --proxy-port "$PORT_MTLS_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_mtls_h2_ok" \
    --client-cert "$CERTS/client.crt" --client-key "$CERTS/client.key"

  banner "[case] mtls / http1 client NO cert (expected fail)\n[case] emulate: proxy требует client cert, но клиент НЕ отправляет; ожидаем tls_in_fail / handshake error в диагностике, без traceback у клиента"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_MTLS_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_mtls_h1_client_no_cert" \
    --no-client-cert

  banner "[case] mtls / h2 client NO cert (expected fail)\n[case] emulate: аналогично, но HTTP/2; ожидаем tls_in_fail / handshake error"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_MTLS_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_mtls_h2_client_no_cert" \
    --no-client-cert

  banner "[case] mtls / http1 client BAD cert (expected fail)\n[case] emulate: proxy требует client cert, клиент отправляет НЕдоверенный/невалидный cert; ожидаем tls_in_fail / handshake error"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_MTLS_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_mtls_h1_client_bad_cert" \
    --client-cert "$CERTS/bad_client.crt" --client-key "$CERTS/bad_client.key"

  banner "[case] mtls / h2 client BAD cert (expected fail)\n[case] emulate: аналогично, но HTTP/2"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_MTLS_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_mtls_h2_client_bad_cert" \
    --client-cert "$CERTS/bad_client.crt" --client-key "$CERTS/bad_client.key"

  banner "[case] mtls / http1 upstream FAIL (expected fail)\n[case] emulate: client->proxy mTLS OK (клиент предъявил валидный cert), но proxy->upstream mTLS ломается (плохой cert/key в upstream); ожидаем upstream handshake/tls error в диагностике"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_MTLS_BADUP_H1" --certs "$CERTS" --sni "$SNI" \
    --proto http1 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_mtls_h1_upstream_fail" \
    --client-cert "$CERTS/client.crt" --client-key "$CERTS/client.key"

  banner "[case] mtls / h2 upstream FAIL (expected fail)\n[case] emulate: аналогично, но HTTP/2"
  run_allow_fail "$PY" "$CLIENT" --quiet-expected \
    --proxy-host "$HOST" --proxy-port "$PORT_MTLS_BADUP_H2" --certs "$CERTS" --sni "$SNI" \
    --proto h2 --mode ok --cycles 1 --interval 0 \
    --path "/mode/ok?tid=${TID_BASE}_mtls_h2_upstream_fail" \
    --client-cert "$CERTS/client.crt" --client-key "$CERTS/client.key"

  # --------------------------------------------------------------------------
  # Останавливаем proxy (если мы его стартовали) ДО verify, чтобы JSONL дозаписался.
  # --------------------------------------------------------------------------
  if [[ "$NO_PROXY" -eq 0 ]]; then
    say "tests finished, stopping proxy..."
    stop_proxy
    trap - EXIT
  else
    say "tests finished (proxy left running)"
    trap - EXIT
  fi

  # --------------------------------------------------------------------------
  # Запускаем verify
  # --------------------------------------------------------------------------
  say "verifying JSONL: $JSONL"
  VERIFY_ARGS=(--jsonl "$JSONL" --tid-base "$TID_BASE" --since "$SUITE_SINCE_EPOCH")
  if [[ "$WITH_GRPC_NATIVE" -eq 1 ]]; then
    VERIFY_ARGS+=(--with-grpc-native)
  fi
  run_cmd "$PY" "$VERIFY" "${VERIFY_ARGS[@]}"

  echo
  say "OK"
}

main "$@"
