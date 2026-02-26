# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.50.0] - 2026-02-26
### Added
- HTTP/2 fingerprinting for H2 connections (`h2fp`):
  - computed from early HTTP/2 peer behavior (`SETTINGS` + first connection-level `WINDOW_UPDATE`);
  - stored per direction and as a combined connection profile;
  - visible in Connections view, connection details, filters, and `h2ctl FINGERPRINT` events.
- Inbound TLS ClientHello fingerprinting before TLS upgrade:
  - `JA3` hash and `ja3_raw`;
  - `JA4` token and `ja4_raw`.
- Inbound encrypted-name signals:
  - `ECH` presence marker and extension length (`ech`, `ech_len`);
  - legacy `ESNI` presence marker (`esni`).
- New filter tokens and UI hints:
  - `h2fp`, `h2fp_in`, `h2fp_out`;
  - `ja3`, `ja4`, `ech`, `ech_len`, `esni`.

### Changed
- TLS inbound rows/details now include ClientHello fingerprint fields when available.
- Connections metadata and details now include inbound JA3/JA4/ECH/ESNI and H2 fingerprints.

### Русский
#### Добавлено
- Fingerprint для HTTP/2 соединений (`h2fp`):
  - вычисляется по раннему поведению peer (`SETTINGS` + первый `WINDOW_UPDATE` уровня соединения);
  - сохраняется по направлениям и как объединенный профиль соединения;
  - отображается в Connections, в деталях, в фильтрах и в событиях `h2ctl FINGERPRINT`.
- Fingerprint входящего TLS ClientHello до TLS upgrade:
  - `JA3` и строка `ja3_raw`;
  - `JA4` и строка `ja4_raw`.
- Сигналы шифрования имени:
  - признак наличия `ECH` и длина extension (`ech`, `ech_len`);
  - признак legacy `ESNI` (`esni`).
- Новые токены фильтрации и подсказки в UI:
  - `h2fp`, `h2fp_in`, `h2fp_out`;
  - `ja3`, `ja4`, `ech`, `ech_len`, `esni`.

#### Изменено
- Входящие TLS-события и Details теперь показывают поля ClientHello fingerprint (если доступны).
- Метаданные и Details соединений теперь включают JA3/JA4/ECH/ESNI и H2 fingerprint.

## [1.40.0] - 2026-02-23
### Added
- Baseline release before fingerprint telemetry features.
- Stable TLS/mTLS diagnostics, HTTP/2 control-plane telemetry, and PROXY protocol support.

### Русский
#### Добавлено
- Базовый релиз до внедрения fingerprint-телеметрии.
- Стабильная диагностика TLS/mTLS, телеметрия HTTP/2 control-plane и поддержка PROXY protocol.
