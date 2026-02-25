# Архитектурные диаграммы (PlantUML)

Одна диаграмма = один `.puml` файл.

## Список диаграмм

1. Общая архитектура компонентов  
   Файл: `diagramms/01-components-overview.puml`

2. Последовательность: TLS handshake + старт HTTP/2  
   Файл: `diagramms/02-tls-h2-startup-sequence.puml`

3. Проксирование одного gRPC запроса (одного stream)  
   Файл: `diagramms/03-grpc-single-stream-sequence.puml`

4. Где появляется `FLOW_BLOCK`  
   Файл: `diagramms/04-h2-flow-block.puml`

5. PROXY protocol: автодетект и проброс в upstream  
   Файл: `diagramms/05-proxy-protocol-autodetect.puml`

6. Connections view: подсветка ошибок и счетчик `Errs`  
   Файл: `diagramms/06-connections-errors-visualization.puml`

## Примечания

- Диаграммы отражают текущее имя проекта: `wiretracer`.
- Диаграмма №5 описывает функционал PROXY protocol.
- Диаграмма №6 описывает отображение ошибок в `Connections` (`Errs` + row highlight).
