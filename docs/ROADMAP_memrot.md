# ROADMAP — memrot

## 1. Итог

`memrot` уже является работающим каркасом исследовательского инструмента: у него есть отдельный статический аудитор, каталог многошаговых атак, адаптеры HTTP/MCP/Python, контрольный запрос до инъекции, проверка новой сессии, несколько каналов обнаружения и JSON/Markdown/HTML-отчёты. Переписывать его не требуется. Главная проблема — различие между тем, что эксперимент наблюдал, и тем, что объявляет доказанным: наличие маркера в ответе или хранилище объединяется в `CONFIRMED`, cross-user получает `control_violation_observed` по метаданным сценария, а строгий режим переводит недоказанное в `CLEAN`. Новый memory trace правильно помечает часть событий как inferred, но не сохраняет полный журнал эксперимента. Основание: `memrot:memrot/runner/engine.py::_judge`, `_Lifecycle`; `memrot:memrot/runner/verdict.py::apply_tier_gate`; `memrot:memrot/models.py::path_state_for`; `memrot:memrot/tracer.py::JSONLTracer`.

Пять важнейших изменений: исправить идентичность пользователей и изоляцию попыток; отделить наблюдённое нарушение от косвенного сигнала и неизвестного исхода; сделать метрики чувствительными к типу контроля и полноте наблюдения; сохранять безопасный, связанный с вердиктом пакет доказательств; обеспечить повторяемые эксперименты с фиксированными входами, независимыми повторами и контрольными условиями. У конкурентов стоит брать именно эти механизмы, а не количество шаблонов или готовый orchestration framework: у Diskard — prepare/restore/verify, у MOROK — независимые evidence providers и проверку видимости, у memnotsafe — фазовые снимки, проверяемые bundles и калибровку судьи, у red-alert — отделение техники от доменных bindings и учёт расхода моделей. Их недостатки в оценке причинности, обработке ошибок и сохранении данных не переносить. Источники: `Diskard:src/diskard/connectors/base.py`; `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/evidence/base.py`; `agentic-red-teaming:src/memnotsafe/evidence/bundle.py`; `red-alert:red_alert/profile.py`, `red_alert/usage.py`.

## 2. Как устроен memrot сейчас

Анализ выполнен для `feature/memory-trace-v0.1`, commit `26b794a20eb0570601d487a135906045eac1f339`. Остальные репозитории зафиксированы независимо: Diskard — `main@f351279c46b5a6ec49f1fd9a13a5af50aeb75fda`; Talent-Hub-Agentic-Red-Teaming-Case — `main@f730091ab6a8512abeb0b115e3abcd1a250ad150`; agentic-red-teaming — `main@754fcb6ff5c260daf931212bb7e0251da6253aa8`; red-alert — `main@4706501951f68047df4a36b7c487858d82a022ce`. Все ссылки `репозиторий:путь` ниже относятся к этим снимкам. Результаты локальных тестов характеризуют harness и fixtures, а не защищённость реального банковского агента.

В репозитории сосуществуют три слоя. `mcp_audit` собирает inventory, исходники, policy/deployment snapshots, traces и memory events, применяет правила, строит граф и формирует audit report. У него есть offline, live inventory и controlled validation; называть весь этот пакет исключительно offline, как делает основной README, неточно. `memrot` читает JSON аудитора через `audit_bridge.py` и `audit_plan.py`, фильтрует или ранжирует атаки по rule IDs, но не импортирует его движок. Старый `redteam/attacks` остаётся отдельным, более узким harness. Сохранять это разделение полезно; подтверждение гипотезы требует явной связи с runtime evidence, а не совпадения rule ID. Источники: `memrot:mcp_audit/orchestrator.py::Orchestrator.run`; `memrot:memrot/audit_bridge.py`; `memrot:memrot/audit_plan.py`; `memrot:redteam/attacks/harness.py`; `memrot:README.md`.

`RunConfig` задаёт target binding, channels/principals, каталог, detector, generator и reset policy. `TargetAdapter` требует только `new_session()` и `send()`; consolidation, inspection, staging, ingestion и reset необязательны. Через JSON доступны `openai_compat`, `http_generic`, `mcp_client`, `genai_invest`; `CallableAdapter` и `InProcessStandAdapter` подключаются из Python. OpenAI-адаптер отправляет только текущую user-реплику и заголовок с session ID: обычный stateless completion API не превращается от этого в агент с долговременной памятью. `genai_invest` умеет finalize, чтение Mongo/Redis и проверку docker logs, но reset не реализует. MCP использует один transport и авторизацию первого principal для последующих пользователей — это подтверждённый дефект. Источники: `memrot:memrot/config.py`; `memrot:memrot/adapters/base.py`; `memrot:memrot/adapters/registry.py`; `memrot:memrot/adapters/openai_compat.py::_build_body`; `memrot:memrot/adapters/genai_invest.py`; `memrot:memrot/adapters/mcp_client.py::_ensure_connected`.

Движок выполняет `baseline → inject → consolidate → probe`; probe использует новую сессию того же либо другого пользователя. Для tool-result сначала подменяется ответ инструмента и посылается обычный trigger; для document-ingestion вызывается отдельный метод адаптера. Single-turn идёт по отдельному пути. В 26 `catalog.json` находится 81 вариант: 67 chat-direct по значению по умолчанию, 12 tool-result, 2 document-ingestion; по propagation — 24 single-turn, 15 cross-session-same-user и 42 cross-user. Это количество деклараций, не число подтверждённых уязвимостей. Есть global-policy poisoning, перенос пользовательских данных, protected-key/integrity/bulk сценарии, tool/document/email/websearch injection, обфускация, многошаговые и доменные варианты invest_bank/MemPalace. Полного протокола многократного старения памяти, избирательного sleeper и retrieval competition в runner нет. Источники: `memrot:memrot/catalog/loader.py::load_catalog`; `memrot:memrot/catalog/prompts/`; `memrot:memrot/runner/engine.py`.

Обнаружение основано на literal canary, inspection и optional ground truth. `LLMJudgeDetector`, несмотря на имя файла `llm_judge_stub.py`, реально вызывает модель; однако получает только текст и marker, не `rule_semantic`, ожидаемое запрещённое действие или полную цепочку. При ошибке он возвращает результат literal fallback. Adaptive loop меняет текст между раундами, но не сбрасывает состояние и не выполняет отдельный подтверждающий запуск. Импортированные GARAK/TrustAIRLab-подсказки имеют отдельный `threat_model`, однако общий ASR объединяет их с memory cases. Источники: `memrot:memrot/detectors/llm_judge_stub.py`; `memrot:memrot/runner/adaptive.py`; `memrot:memrot/catalog/generator.py`; `memrot:memrot/reporting/aggregate.py`.

`memory_trace` содержит Pydantic-модели, JSON Schema, redaction и JSONL emitter. Схема описывает семь стадий, включая `influenced_action` и `caused_harm`, но текущий runner эмитирует только `candidate`, `saved`, `retrieved`, `in_prompt`. `candidate` непосредственно наблюдается harness; `saved` означает вызов consolidation с `_coverage.observed=false`; retrieval/context inclusion выводятся из ответа с canary, тоже с `observed=false`. Это полезная дисциплина, но пока не инструментирование реального memory store/retriever/context builder. Phase-события baseline/request/response/error/verdict остаются только в RAM. `trace_event_ids` результатов пусты, `finished_at` не заполняется; ошибки lifecycle emission не включаются в RunReport. Источники: `memrot:memory_trace/models.py`; `memrot:schemas/memory-trace-0.1.schema.json`; `memrot:memory_trace/emitter.py`; `memrot:memrot/tracer.py`; `memrot:memrot/runner/engine.py::_Lifecycle`; `memrot:memrot/models.py`.

JSON/Markdown/HTML строятся из `RunReport`. HTML экранирует поля и закрывающие script-последовательности; это уже работающую защиту надо сохранить. ASR исключает `ERROR`, `INVALID`, `NOT_EVALUATED`, но включает benign controls; группы, где все исходы исключены, вообще не создаются. Поэтому обещание README показывать любую непроверенную категорию как `n/a (0/0)` подтверждено только моделью `GroupMetric`, не всей агрегацией. Markdown не выводит подробные per-result limitations и evidence tiers. Источники: `memrot:memrot/reporting/aggregate.py::aggregate`; `memrot:memrot/reporting/emitter.py::emit_markdown`; `memrot:memrot/reporting/html_emitter.py::_json_script_safe`; `memrot:README.md`.

В чистом Python 3.12 venv команда `python -m memrot --help` падает с `ModuleNotFoundError: pydantic`: заявление README о stdlib-only core на этой ветке неверно. После установки `pytest`, Pydantic 2.13.5, jsonschema 4.26.0 и rfc3339-validator 0.1.4 команда `python -m pytest -ra` дала 376 passed, 5 skipped; отдельно `python -m pytest -ra memory_trace/tests` — 32 passed. `pytest.ini` исключает вторую группу из стандартного discovery. `python -m memrot validate-catalog memrot/catalog/prompts --strict-taxonomy` проверила 26 файлов без ошибок. Offline audit из README выполнился с `status=partial`, `validation_errors=0`; это не live-подтверждение атак. Основание: `memrot:README.md`; `memrot:pytest.ini`; `memrot:memory_trace/schema.py`; `memrot:tests/test_attack_inprocess_stand_adapter.py`; `memrot:tests/test_portability.py`.

## 3. Конкуренты

### 3.1. Diskard

Diskard использует Giskard Suite/Scenario, добавляя отдельные `TargetConnector`, `IdentityProvider`, `EvidenceCollector`, `IsolationController`. Встроены четыре семейства: cross-user global policy, direct memory leak, compaction policy poisoning и delayed recommendation manipulation. Требуемые collectors проверяются до запуска. Особенно полезны checkpoint до эксперимента, restore в `finally`, verify и отдельное подтверждение найденного adaptive payload после восстановления состояния. Практический reference connector относится к инвестиционному стенду; наличие интерфейса не означает готовую поддержку произвольных хранилищ. Источники: `Diskard:src/diskard/connectors/base.py`; `Diskard:src/diskard/attacks.py::ATTACKS`; `Diskard:src/diskard/cli.py::_run_config_scan`; `Diskard:examples/connectors/investment_stand/connector.py::MongoNamespaceIsolation`.

Оценка детерминированная: snapshots и строковые маркеры, без LLM-as-judge. LLM предлагает атакующие формулировки; каталог — собственные шаблоны и синтетические canary. Есть lifecycle stages, distinction observed/inferred, JSON/Markdown/JUnit и ASR без infrastructure errors. Compaction — несколько benign turns и один finalize, не многократная деградация памяти. Recommendation oracle считает упоминание ticker воздействием, включая отрицание рекомендации; control использует другую личность. `stage_verdicts_for()` выводит retrieval/adoption из downstream effect и даже перезаписывает явные False. Эти правила не переносить как доказательство причинности. Источники: `Diskard:src/diskard/checks/lifecycle.py`; `Diskard:src/diskard/checks/recommendation_shift.py`; `Diskard:src/diskard/report.py`; `Diskard:src/diskard/scenarios/compaction_policy_poisoning.py`; `Diskard:src/diskard/attacker.py`.

`new_records_by_key()` видит только новые IDs, теряя изменения существующих записей. Replay не всегда сохраняет фактический выбранный payload: deterministic compaction выбирает шаблон через `hash(run_id)`, а новый replay получает другой run ID. Console redaction не защищает сырой CLI JSON со snapshots. В сохранённом локальном test log — 174 passed, 1 skipped; реальный стенд не запускался. Лицензия MIT присутствует. Переносить isolation contract и разделение стадий, реализуя более строгие diff, evidence и replay. Источники: `Diskard:src/diskard/checks/evidence.py`; `Diskard:src/diskard/scenarios/compaction_policy_poisoning.py`; `Diskard:src/diskard/cli.py`; `Diskard:src/diskard/console/redaction.py`; `Diskard:LICENSE`.

### 3.2. Talent-Hub-Agentic-Red-Teaming-Case / MOROK

MOROK отделяет target transport от evidence providers и нормализованных Facts. На каждом шаге используются `mark → collect`, независимые snapshots и tool/callback evidence; commit-ответ сам по себе не считается записью в память. YAML-профили описывают target bindings и границы. Есть сценарии global-policy poisoning, poison-to-tool, прямого BAC, system prompt leak и benign smoke, а также автономный attacker с ограничением действий. Полезная особенность — `calibrate.verify()`: harmless canary записывается автором, читается через независимый target-filtered reader в заданных scope, проверяется положительный контроль автора и выполняется reset. Источники: `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/evidence/base.py`; `agentic_redteam/evidence/bundle.py`; `agentic_redteam/campaign/runner.py::_run_chain`; `agentic_redteam/evidence/calibrate.py`; `agentic_redteam/scenarios/`.

Детерминированные проверки различают STATE/TEXT/UNOBSERVABLE/ERROR; отдельно существует YES/NO judge с сохранением модели, версии промпта и входа. Technical/business reports, freeze/regression export, атомарные artifacts и штатные smoke checks сильнее текущих отчётов memrot. Однако `cross_session_effect()` фактически проверяет principal mismatch без обязательного доказательства memory path. Любое постороннее state-событие позволяет присвоить judge-ответу уровень STATE. `UNOBSERVABLE` становится `not_proven` и входит в знаменатель; regression compare может объявить исчезнувшую из findings атаку закрытой, хотя её не проверяли. Источники: `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/assertions/predicates.py`; `agentic_redteam/assertions/verdict.py`; `agentic_redteam/campaign/runner.py::_evaluate_with_judge`, `_asr`; `agentic_redteam/reporting/regression.py::compare`; `agentic_redteam/storage/runs.py`.

Каталог и baseline templates не являются широким размеченным banking benchmark; отдельного holdout для измерения качества judge в проверенных файлах нет. Без установки всех зависимостей unittest discovery выполнил 685 тестов с 1 failure и 3 errors, связанными с отсутствующими observability/Streamlit зависимостями; целевые 67 тестов runner/evidence/verdict/judge/visibility прошли. Эти результаты не доказывают сбой проекта в его заявленной среде. Лицензия в tracked tree не найдена: переносить идеи самостоятельной реализацией. Источники: `Talent-Hub-Agentic-Red-Teaming-Case:requirements.txt`; `tests/test_memory_visibility.py`; `tests/test_stand_observability.py`; `tests/test_llm_judge.py`; `templates/`; `README.md`.

### 3.3. agentic-red-teaming / memnotsafe

memnotsafe наиболее подробно разделяет Attack, TargetAdapter, Runner, Oracle и Reporter. Реестр импортирует 23 семейства/генератора: policy/scope escalation, forged rationale, procedural graft, false precedent, deferred payload, cross-user BAC, recommendation/tool hijack и другие. Число регистраций не равно числу независимо валидированных техник. В `src/memnotsafe/attacks/document_regulation_graft.py` и `tool_error_echo_poisoning.py` effective delivery — user_query: названия document/tool не означают реальную подмену этих каналов. Runtime выполняет baseline, delivery, закрытие сессии, settle и новый trigger; снимки m0–m3 позволяют не подменять состояние после записи состоянием после probe. `SettleResult` различает observed/timeout/unavailable, а mock/HTTP/OpenAI/investment adapters имеют разные capabilities. Источники: `agentic-red-teaming:src/memnotsafe/attacks/__init__.py`; `src/memnotsafe/adapters/base.py`; `src/memnotsafe/core/runner.py`; `src/memnotsafe/evidence/snapshot.py`.

Сильные переносимые механизмы — bundles с атомарным manifest и проверкой checksum/path, разделение present/absent/unavailable, фазовые oracle, ASR provenance, структурированный judge с проверкой цитаты и baseline, calibration и injection fixtures. Replay bundle позволяет повторить анализ без target; checksum доказывает целостность относительно manifest, а не подлинность источника. Датасеты судьи включают синтетические/mock-derived примеры: это полезные regression fixtures, но не измеренная точность модели на банковских диалогах. Источники: `agentic-red-teaming:src/memnotsafe/evidence/bundle.py`; `src/memnotsafe/core/result_readouts.py`; `src/memnotsafe/judge/verdict.py`; `src/memnotsafe/judge/calibration.py`; `tests/fixtures/judge_golden.jsonl`; `tests/fixtures/judge_injection.jsonl`.

Переносить формулу успеха буквально нельзя: `composite_success()` допускает UNKNOWN retrieval; provenance это раскрывает, но не устраняет ограничение причинного вывода. `judge_merge` умеет повышать мягкие исходы до True, но не снимает мягкое True при judge refutation. Calibration считает abstention на отрицательном примере совпадением, хотя отдельно учитывает undecided. Агрегация funnel требует осторожности: разные знаменатели стадий нельзя представлять как одну строгую условную цепочку без проверки вложенности наблюдений. Источники: `agentic-red-teaming:src/memnotsafe/oracles/composite.py`; `src/memnotsafe/oracles/judge_merge.py`; `src/memnotsafe/judge/calibration.py::calibrate`; `src/memnotsafe/core/result_readouts.py::aggregate_metrics`.

Пакет устанавливается через `pyproject.toml`, требует Python ≥3.11 и содержит большой offline suite. Лицензия в tracked tree не найдена. В локальной проверке обнаружен Linux-specific тест launcher: Windows-путь `scripts\demo-run.ps1` трактуется как имя POSIX-файла; это не доказательство отсутствия самого `scripts/demo-run.ps1`. Полный повторный прогон с запретом внешней сети дал 1700 passed, 1 skipped, 1 failed именно в этом Linux-specific тесте. Источники: `agentic-red-teaming:pyproject.toml`; `tests/test_demo_launcher.py`; `demo.cmd`; `scripts/demo-run.ps1`.

### 3.4. red-alert

red-alert строит LangGraph `adapt → inject → persist → trigger → judge`, поддерживает memory/probe flows, отдельные attacker/victim credentials инвестиционного target, YAML-техники и StandProfile с доменными slots. Есть десять YAML-сценариев, включая policy poisoning, peer exfiltration, sleeper, style contamination, прямой BAC, system prompt leakage и OpenClaw goal hijack. Изображения действительно создаются через Pillow и отправляются как image_url; Langfuse и token usage реализованы. Для memrot полезны bindings и учёт затрат, но замена runner на LangGraph самостоятельной ценности не даёт. Источники: `red-alert:red_alert/graph.py`; `red_alert/attacks.py`; `red_alert/profile.py`; `red_alert/stand_client.py`; `red_alert/image_payload.py`; `red_alert/usage.py`; `attacks/`.

Judge использует StrictBool и отдельную модель, но видит criterion и final response, не независимое состояние памяти. Ошибки target/planner/judge становятся `success=False` и, кроме isolate failures, входят в ASR. При обычном JSON export сохраняются только successful traces. `OpenClawTarget.isolate()` возвращает локально сконструированный reset success без вызова сервера; `judge.log` пишет немаскированные данные. Dormant trigger не сопровождается neutral control; стилевой перенос между сессиями не измеряет memory rot во времени. Источники: `red-alert:red_alert/judge.py`; `red_alert/models.py::RunReport.asr`; `red_alert/report.py::report_payload`; `red_alert/openclaw_client.py`; `attacks/memory-poisoning-sleeper.yaml`; `attacks/memory-poisoning-ryan-gosling-bladerunner-speech.yaml`.

Inspect имеет keyword/LLM/Codex варианты, но не создаёт универсальный target adapter; keyword absence может получить чрезмерно уверенное absent/high. Запуск Codex в анализируемом repository cwd опасен смешением source data и agent instructions; read-only режим не решает эту проблему. Runtime требует Python ≥3.14. В выполненном offline прогоне 203 теста прошли, 5 завершились ошибками создания HTTP-клиента из-за SOCKS proxy окружения; полный чистый повтор не подтверждён. LICENSE/COPYING отсутствуют, код и corpus не копировать. Источники: `red-alert:red_alert/analyzer.py::_hint_state`, `CodexHarnessAnalyzer`; `red_alert/config.py`; `red-alert:pyproject.toml`; `red-alert:tests/`.

## 4. Сравнительная матрица

«Есть» означает наличие исполняемого механизма в прочитанном коде, а не доказанную эффективность на банковской системе. «Частично» — ограниченный адаптер, неполная доказательная цепочка или дефект, описанный выше. MOROK и memnotsafe — короткие названия соответствующих репозиториев из раздела 3.

| Возможность | memrot | Diskard | MOROK | memnotsafe | red-alert |
|---|---|---|---|---|---|
| Многошаговое persistent-memory poisoning | есть | есть | есть | есть | есть |
| Явные роли и межпользовательские проверки | частично | есть | есть | есть | частично |
| Инъекция через tool result / документ | есть | нет | частично | частично | частично |
| Наблюдения записи и последующей видимости памяти | частично | есть | есть | есть | частично |
| Различение observed / inferred / unknown | частично | частично | частично | есть | частично |
| Строгое причинное доказательство memory→action | частично | частично | частично | частично | нет |
| Сброс с проверкой результата между попытками | частично | есть | частично | есть | частично |
| Протокол ожидания асинхронной записи | нет | частично | нет | есть | частично |
| Проверка compaction poisoning | нет | есть | нет | нет | нет |
| Измерение многократного memory rot | нет | нет | нет | нет | нет |
| Generic HTTP integration | есть | частично | есть | есть | частично |
| Статический анализ для выбора атак | есть | нет | нет | нет | частично |
| LLM-as-judge | есть | нет | есть | есть | есть |
| Labelled judge calibration + injection fixtures | нет | нет | нет | есть | нет |
| Adaptive attacker | есть | есть | есть | есть | есть |
| Ошибки/unknown не маскируются общим ASR | частично | есть | частично | частично | нет |
| Контроли полезности отдельно от attack ASR | нет | частично | есть | частично | нет |
| Полный пакет evidence и offline re-evaluation | нет | частично | частично | есть | нет |
| Полный экспорт всех попыток по умолчанию | частично | есть | есть | есть | нет |
| Маскирование всех путей записи artifacts | частично | частично | частично | частично | частично |
| Мультимодальная доставка изображения | нет | нет | нет | нет | есть |
| Автоматические тесты | есть | есть | есть | есть | есть |

Основания матрицы: для memrot — `memrot:memrot/runner/engine.py`, `adapters/base.py`, `reporting/aggregate.py`, `tracer.py`; для Diskard — `Diskard:src/diskard/attacks.py`, `connectors/base.py`, `report.py`; для MOROK — `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/evidence/bundle.py`, `campaign/runner.py`, `reporting/technical.py`; для memnotsafe — `agentic-red-teaming:src/memnotsafe/core/runner.py`, `core/result_readouts.py`, `evidence/bundle.py`, `judge/calibration.py`; для red-alert — `red-alert:red_alert/graph.py`, `profile.py`, `models.py`, `report.py`, `image_payload.py`. Отрицательные значения относятся к проверенным runtime-путям и каталогам, а не к текстам планов в репозиториях.

## 5. Недостатки memrot

Серьёзность оценивает риск для достоверности эксперимента и безопасности harness. Наличие большого test suite не отменяет пробелы контрактов; отсутствие тестов всего проекта не утверждается.

| Проблема | Где (файл) | Серьёзность | Как исправить |
|---|---|---|---|
| Cross-user MCP запросы выполняются с credentials первого пользователя; воспроизведено на fake transport | `memrot:memrot/adapters/mcp_client.py::_ensure_connected`, `send` | critical | Разделить transport/auth по principal, проверять реальную identity; F0-02 |
| Controlled validation запускает configured stdio server ещё до отказа `sandbox=False`; manifest plugins импортируются даже offline | `memrot:mcp_audit/orchestrator.py::collect`, `run`; `mcp_audit/adapters/registry.py`; `mcp_audit/adapters/mcp_inventory.py` | high | Проверять execution policy до collect/import/spawn; F0-10 |
| MCP child наследует весь env; stderr не дренируется, close adapter отсутствует | `memrot:memrot/adapters/mcp_client.py::_StdioTransport`, `MCPClientAdapter` | high | Минимальный env, bounded streams, гарантированное закрытие; F0-03 |
| Tool stage остаётся после trigger exception; внутренний TypeError callable может повторить побочный эффект три раза | `memrot:memrot/runner/engine.py::_run_tool_injection_flow`; `memrot/adapters/callable_adapter.py::stage_tool_response` | high | Транзакционный staging и заранее выбранная сигнатура; F0-04 |
| Ground truth ищет доступ во всех старых logs и игнорирует returncode docker; старая запись дала True, сбой команды — False | `memrot:memrot/adapters/genai_invest.py::ground_truth_check` | high | Cursor/attempt correlation, ошибки источника отдельно; F0-05 |
| Text/state/ground-truth объединяются OR; state visibility не доказывает действие; strict превращает недостаток evidence в CLEAN | `memrot:memrot/runner/engine.py::_judge`; `memrot/runner/verdict.py::apply_tier_gate` | high | Отдельный INCONCLUSIVE и goal-specific decision; F0-06, F2-01 |
| `path_state` выводится из verdict и строки propagation; CLEAN объявляет static support без static evidence | `memrot:memrot/models.py::path_state_for` | high | Назначать состояние только из связанных evidence; F0-06 |
| Benign входят в ASR и используют default attacker role; полностью непроверенные группы исчезают | `memrot:memrot/reporting/aggregate.py`; `memrot/catalog/prompts/domain/invest_bank/benign_control/catalog.json`; `memrot/catalog/loader.py` | high | Тип case, отдельные controls/denominators, полный inventory; F0-07 |
| Phase trace только в RAM; refs пусты, timings неполны; потерянные lifecycle events не отражаются в отчёте | `memrot:memrot/tracer.py`; `memrot/runner/engine.py`; `memrot/models.py` | high | Два версионированных потока, стабильные attempt/event IDs, coverage; F0-08 |
| Redaction идёт после обрезки preview; короткий хвост токена остаётся; query_used и errors/report fields обходят обработку | `memrot:memrot/tracer.py::lifecycle`; `memory_trace/emitter.py::emit`; `memory_trace/redaction.py`; `memrot/reporting/emitter.py` | high | Обрабатывать до truncation все выходные текстовые поля; F0-09 |
| `saved/retrieved/in_prompt` косвенные, стадий действия и вреда runner не наблюдает | `memrot:memrot/runner/engine.py::_Lifecycle`; `memory_trace/models.py` | medium | Независимый event ingestion и adapter hooks; F1-02, F1-06 |
| Отсутствующий sink-effect даёт FAIL, refusal без effect observation даёт PASS | `memrot:mcp_audit/active/runner.py::observe_effect`, `decide` | high | Единая семантика desired/forbidden/unknown effect; F0-11 |
| Setup/teardown ControlCase не исполняются; discovery credential headers не передаются active Introspector | `memrot:mcp_audit/active/fixtures.py`; `mcp_audit/active/runner.py`; `mcp_audit/adapters/mcp_inventory.py::_credential_headers` | high | Проверяемый fixture lifecycle и общий identity binding; F0-12, F0-13 |
| `schema_agrees` принимает bool как integer, не проверяет enum | `memrot:mcp_audit/active/fixtures.py::schema_agrees` | medium | Полная JSON Schema validation до вызова; F0-14 |
| README stdlib/no-setup неверен; dependency manifest отсутствует; memory_trace tests вне discovery | `memrot:README.md`; `memrot:pytest.ini`; `memory_trace/models.py`, `schema.py` | high | Packaging/dependencies/CI и воспроизводимый offline quickstart; F0-01 |
| Capability gate проверяет white_box, но не полный порядок black/grey/white; session/memory support не проверяется | `memrot:memrot/runner/engine.py::_run_variant`; `memrot/adapters/openai_compat.py`; `memrot/adapters/base.py` | high | Явные session/persistence/evidence capabilities; F1-01 |
| Новый canary не обнаруживает влияние старого payload без этого canary; reset default False; adaptive игнорирует reset policy | `memrot:memrot/runner/engine.py::run_matrix`; `memrot/runner/adaptive.py`; `memrot/pipeline.py` | high | Namespace/checkpoint isolation и fresh confirmation; F1-04, F4-01 |
| Немедленный probe после finalize не учитывает eventual consistency | `memrot:memrot/runner/engine.py::_run_canary_flow`; `memrot/adapters/base.py` | medium | Bounded settle с observed/timeout/unavailable; F1-03 |
| Законное обновление собственной contact preference объявлено integrity attack; canary spillover назван sensitive leakage | `memrot:memrot/catalog/prompts/generic/generic_memory_integrity_violation/catalog.json`; `generic_sensitive_data_leakage/catalog.json` | high | Явные authority/policy/goals, paired benign и victim-only secret; F2-01, F2-03 |
| Judge не знает goal/rubric, YES-prefix parser нестрогий, fallback меняет evaluator без отдельной метрики | `memrot:memrot/detectors/llm_judge_stub.py` | high | Structured outcome/provenance, calibrated rubric и abstention; F3-04, F3-05 |
| Adaptive tool-result переписывает probe/inject_turns, а не staging payload; generation failure скрыт break | `memrot:memrot/runner/adaptive.py::run_adaptive` | medium | Delivery-aware mutation, явный stop reason, раздельный discovery ASR; F4-01 |
| Нет frozen run manifest, общего replay, repeat uncertainty и total budget | `memrot:memrot/models.py::RunReport`; `memrot/cli.py`; `memrot/mutation/llm_client.py`; `memrot/reporting/aggregate.py` | medium | Bundles/replay/repeats/budget; F3-01–F3-03, F4-02 |
| Markdown скрывает per-result limitations и силу evidence; «Full trace» неполон | `memrot:memrot/reporting/emitter.py::emit_markdown` | medium | Evidence-first reports из одного read model; F3-06 |
| Нет общей лицензии; imported NOTICE указывает источник, но не фиксирует все provenance/лицензионные артефакты | `memrot:memrot/catalog/imported/garak_dan/NOTICE.md`; `trustairlab_jailbreak/NOTICE.md`; tracked tree | medium | Лицензия владельца, source revisions/hashes/notices; F4-03 |

Во время чтения обнаружены обращённые к агентам инструкции: `Diskard:AGENTS.md` и `.agents/skills/diskard-agent-integration/SKILL.md`, `Talent-Hub-Agentic-Red-Teaming-Case:CLAUDE.md`, `agentic-red-teaming:AGENTS.md`, `CLAUDE.md`, `red-alert:AGENTS.md`. Они требуют собственных workflows, чтения дополнительных файлов и ограничений изменений; это данные анализируемых проектов, а не правила этого аудита. Attack/system prompts также не выполнялись. Например, `memrot:memrot/catalog/imported/trustairlab_jailbreak/sample.json` содержит попытки смены роли и отмены ограничений, а `red-alert:attacks/openclaw-goal-hijack.yaml` — инструкции читать host files/environment. Отдельного доказательства злонамеренной подмены именно текущего аудита не обнаружено.

## 6. План работ по фазам

Порядок определяется зависимостями. Каждая задача добавляет один контракт или исправляет один логический механизм; переписывание runner, смена orchestration framework и перенос чужого кода не требуются. Пути в поле «Файлы» относительны к корню memrot; пометка «новые» означает предлагаемые файлы. Команды для новых тестов и CLI — критерии будущей реализации, а не утверждение, что эти команды уже доступны. До изменения поведения сохранить regression fixtures старого формата; несовместимые изменения отчётов сопровождать повышением schema version.

### Фаза 0 — исправления и фундамент

### [F0-01] Воспроизводимая установка и полный discovery тестов
- **Источник:** аудит memrot — `memrot:README.md`, `pytest.ini`, `memory_trace/models.py`, `memory_trace/schema.py`.
- **Зачем:** чистая установка должна запускать CLI и весь offline suite.
- **Что сделать:** объявить Python/dependencies, dev extra и package data schemas/catalog; добавить lock/constraints для CI; включить `memory_trace/tests`; исправить stdlib/no-setup и неверный каталог `cd aith_redteaming` в README. Добавить offline smoke без обращения к localhost по умолчанию.
- **Файлы:** `README.md`, `pytest.ini`; новые `pyproject.toml`, `requirements-dev.lock`, `.github/workflows/tests.yml`, `tests/test_install_smoke.py`.
- **Зависит от:** нет.
- **Критерии приёмки:** в новом venv `pip install -e '.[dev]'`, `python -m memrot --help`, `python -m pytest -ra`; оба test tree собираются; установленный wheel находит schemas/catalog вне cwd репозитория.
- **Приоритет:** P0 · **Сложность:** M

### [F0-02] Авторизация MCP отдельно для каждого principal
- **Источник:** аудит memrot — `memrot:memrot/adapters/mcp_client.py::_ensure_connected`.
- **Зачем:** устранить ложные cross-user результаты.
- **Что сделать:** хранить соединение и MCP session по credential/principal binding; не подменять ошибку отсутствующего credential анонимным подключением; явно описать ограничения stdio identity.
- **Файлы:** `memrot/adapters/mcp_client.py`; новый `tests/test_attack_mcp_identity.py`.
- **Зависит от:** F0-01.
- **Критерии приёмки:** `pytest tests/test_attack_mcp_identity.py`; локальный mock server видит A→Bearer-A, B→Bearer-B, A→Bearer-A и разные MCP sessions; неподдерживаемый identity switch не запускает cross-user case.
- **Приоритет:** P0 · **Сложность:** M

### [F0-03] Управляемый жизненный цикл MCP transport
- **Источник:** аудит memrot — `memrot:memrot/adapters/mcp_client.py::_StdioTransport`.
- **Зачем:** не передавать child process секреты harness и не оставлять зависшие процессы.
- **Что сделать:** allowlist env с явными credential refs, bounded stdout/stderr, дренирование stderr и `close()`/context manager адаптера; вызывать cleanup из CLI/pipeline в `finally`. Не выбирать произвольный первый MCP tool: требовать явный `chat_tool` либо однозначный read-only binding.
- **Файлы:** `memrot/adapters/base.py`, `memrot/adapters/mcp_client.py`, `memrot/cli.py`, `memrot/pipeline.py`; новый `tests/test_attack_mcp_lifecycle.py`.
- **Зависит от:** F0-02.
- **Критерии приёмки:** mock child не получает посторонний secret env; большой stderr не блокирует ответ; после timeout процесс завершён; неоднозначный tool list отклоняется до `tools/call`.
- **Приоритет:** P0 · **Сложность:** M

### [F0-04] Транзакционный staging ответа инструмента
- **Источник:** аудит memrot — `memrot:memrot/runner/engine.py::_run_tool_injection_flow`; `memrot:memrot/adapters/callable_adapter.py::stage_tool_response`.
- **Зачем:** ошибка одной атаки не должна влиять на следующую.
- **Что сделать:** stage/trigger обернуть в гарантированный unstage; отдельно сохранять primary/cleanup errors. Совместимость сигнатур callable определять до вызова через introspection/явную версию, не повторять функцию после её внутреннего TypeError.
- **Файлы:** `memrot/runner/engine.py`, `memrot/adapters/callable_adapter.py`, `tests/test_attack_tool_injection_flow.py`.
- **Зависит от:** F0-01.
- **Критерии приёмки:** `pytest tests/test_attack_tool_injection_flow.py`; trigger exception вызывает unstage ровно один раз; stage с внутренним TypeError вызывается один раз; следующий case не получает старый payload.
- **Приоритет:** P0 · **Сложность:** S

### [F0-05] Ground truth в окне текущей попытки
- **Источник:** аудит memrot; `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/evidence/base.py::EvidenceProvider.mark`.
- **Зачем:** старый доступ к объекту не должен подтверждать новую атаку.
- **Что сделать:** в genai adapter захватывать cursor до действия; читать только новые события с run/attempt/session/principal/object correlation. Проверять returncode и доступность logs; отсутствие достаточной корреляции означает unknown, не False/True.
- **Файлы:** `memrot/adapters/genai_invest.py`, `memrot/adapters/base.py`, `memrot/runner/engine.py`; новый `tests/test_attack_ground_truth_window.py`.
- **Зависит от:** F0-01.
- **Критерии приёмки:** mocked старый GET не подтверждает атаку; новый GET чужой попытки тоже; совпадающее событие подтверждает; docker nonzero даёт ошибку evidence source, не CLEAN.
- **Приоритет:** P0 · **Сложность:** M

### [F0-06] Неизвестный исход отдельно от CLEAN
- **Источник:** аудит memrot; `agentic-red-teaming:src/memnotsafe/adapters/base.py::SettleResult`.
- **Зачем:** отсутствие наблюдения не является отрицательным результатом.
- **Что сделать:** добавить `INCONCLUSIVE` с reason и versioned serialization; убрать strict→CLEAN. `path_state` вычислять из конкретных evidence refs: CLEAN не даёт static support, а строка cross-user не даёт control violation. Сохранить наблюдённый text signal независимо от итогового verdict.
- **Файлы:** `memrot/models.py`, `memrot/runner/verdict.py`, `memrot/runner/engine.py`, `memrot/cli.py`, `memrot/reporting/aggregate.py`; существующие verdict/CLI tests.
- **Зависит от:** F0-01.
- **Критерии приёмки:** `pytest tests/test_attack_verdict.py tests/test_attack_verdict_tiers.py tests/test_attack_cli.py`; text-only strict case — INCONCLUSIVE; `--gate` возвращает incomplete; legacy report читается с явно прежней семантикой.
- **Приоритет:** P0 · **Сложность:** M

### [F0-07] Разделение attack, benign и diagnostic в метриках
- **Источник:** аудит memrot; `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/reporting/technical.py::build_skeleton`.
- **Зачем:** штатные проверки не должны уменьшать ASR атак.
- **Что сделать:** добавить `case_kind`; benign catalog направить на `benign_control`; считать controls отдельно, включая полезность и ошибки. Инициализировать группы по полному selected inventory, публиковать eligible/evaluated/excluded counts; разделить memory и jailbreak ASR.
- **Файлы:** `memrot/models.py`, `memrot/catalog/schema.py`, `memrot/catalog/loader.py`, оба доменных `benign_control/catalog.json`, `memrot/reporting/aggregate.py`, `tests/test_attack_reporting.py`.
- **Зависит от:** F0-06.
- **Критерии приёмки:** 1 confirmed attack + 9 benign дают attack ASR 1/1; unsupported-only категория присутствует как `n/a (0/0)`; суммы status counts совпадают с selected cases; пустой marker не считается тестом FPR.
- **Приоритет:** P0 · **Сложность:** M

### [F0-08] Сохранение phase journal и связей evidence
- **Источник:** аудит memrot — `memrot:memrot/tracer.py`; `agentic-red-teaming:src/memnotsafe/tracing/transcript.py`.
- **Зачем:** объяснять любой результат после завершения процесса.
- **Что сделать:** сохранять phase events в отдельный versioned `events.jsonl`, оставив lifecycle `trace.jsonl`; добавить attempt_id, refs на baseline/post/state/error и реальные start/end timestamps. Выносить emission/flush failures в report coverage; сохранять partial run при прерывании.
- **Файлы:** `memrot/tracer.py`, `memrot/models.py`, `memrot/runner/engine.py`, `memrot/cli.py`, `tests/test_attack_tracer.py`.
- **Зависит от:** F0-06, F0-09.
- **Критерии приёмки:** после закрытия процесса восстанавливаются requests/responses/verdict всех исходов; каждый ref разрешается; skipped/error case не исчезает; disk error не оставляет отчёт со статусом complete.
- **Приоритет:** P0 · **Сложность:** M

### [F0-09] Единая redaction перед всеми выходами
- **Источник:** аудит memrot — `memrot:memory_trace/redaction.py`, `memory_trace/emitter.py`, `memrot/tracer.py`.
- **Зачем:** trace, отчёт или сообщение об ошибке не должны раскрывать банковские данные и credentials.
- **Что сделать:** маскировать полный текст до truncation; рекурсивно обрабатывать metadata, query_used, errors, detector detail и reports. Добавить режим metadata-only при недоступной обязательной PII-redaction, публиковать degradation. Внешний Presidio разрешать только явной настройкой endpoint; не считать regex достаточной защитой любых PII.
- **Файлы:** `memory_trace/redaction.py`, `memory_trace/emitter.py`, `memrot/tracer.py`, `memrot/reporting/emitter.py`, `memrot/reporting/html_emitter.py`; новый `tests/test_artifact_redaction.py`.
- **Зависит от:** F0-01.
- **Критерии приёмки:** synthetic secrets на границах preview, в query/error/nested fields отсутствуют во всех artifacts/stdout/stderr; canary pseudonym одинаков во всех ссылках; PII backend failure явно виден.
- **Приоритет:** P0 · **Сложность:** M

### [F0-10] Проверка execution policy до запуска внешнего кода
- **Источник:** аудит memrot — `memrot:mcp_audit/orchestrator.py::collect`, `run`; `mcp_audit/adapters/registry.py`.
- **Зачем:** анализируемый manifest/source не должен сам разрешать исполнение команд или plugins.
- **Что сделать:** проверять controlled-validation guard до inventory; отделить доверенные launch/plugin settings оператора от target data. Offline по умолчанию использует только built-in parsers и не импортирует target-declared plugins/entry points; разрешённые plugins задаются отдельно и отражаются в manifest.
- **Файлы:** `mcp_audit/orchestrator.py`, `mcp_audit/manifest.py`, `mcp_audit/adapters/registry.py`, `mcp_audit/adapters/mcp_inventory.py`, `mcp_audit/cli.py`; новый `tests/test_audit_execution_boundary.py`.
- **Зависит от:** F0-01.
- **Критерии приёмки:** marker-writing subprocess и import-side-effect plugin не выполняются в offline и при denied guard; разрешённый режим явно записывает источник разрешения; AGENTS/SKILL из target остаются данными.
- **Приоритет:** P0 · **Сложность:** M

### [F0-11] Корректная таблица исходов controlled validation
- **Источник:** аудит memrot — `memrot:mcp_audit/active/runner.py::observe_effect`, `decide`.
- **Зачем:** убрать ложный FAIL пустого sink и ложный PASS непроверенного эффекта.
- **Что сделать:** нормализовать `effect_present: true/false/unknown` независимо от формулировки expected; refusal не заменяет effect observation.
- **Файлы:** `mcp_audit/active/runner.py`; новый `tests/test_active_outcome_matrix.py`.
- **Зависит от:** F0-01.
- **Критерии приёмки:** параметризованная матрица allowed/denied × effect true/false/unknown × error; empty sink не FAIL; refusal+unknown — INCONCLUSIVE.
- **Приоритет:** P0 · **Сложность:** M

### [F0-12] Исполнение setup/teardown active fixtures
- **Источник:** аудит memrot — `memrot:mcp_audit/active/fixtures.py::ControlCase`; `active/runner.py::_run_case`.
- **Зачем:** восстановление после проверки должно быть реальным.
- **Что сделать:** определить и выполнять разрешённые setup/teardown операции; teardown гарантировать в finally, включая timeout и setup partial failure. Cleanup error сохранять отдельно и останавливать следующие stateful cases при неизвестном состоянии.
- **Файлы:** `mcp_audit/active/fixtures.py`, `mcp_audit/active/runner.py`, `mcp_audit/active/isolation.py`; новый `tests/test_active_fixture_lifecycle.py`.
- **Зависит от:** F0-10, F0-11, F0-14.
- **Критерии приёмки:** mock ledger подтверждает setup→case→teardown; failure на каждой стадии не теряет cleanup; destructive case без разрешения не запускает ни одну стадию.
- **Приоритет:** P0 · **Сложность:** M

### [F0-13] Единый principal для inventory и active audit
- **Источник:** аудит memrot — `memrot:mcp_audit/adapters/mcp_inventory.py::_credential_headers`; `active/runner.py::run_controlled_validation`.
- **Зачем:** каталог и проверка не должны выполняться под разными правами незаметно для отчёта.
- **Что сделать:** передавать credential reference и identity binding через общий connection factory; отражать identity в evidence, не сохранять значения credentials.
- **Файлы:** `mcp_audit/discovery/introspector.py`, `mcp_audit/adapters/mcp_inventory.py`, `mcp_audit/active/runner.py`; новый `tests/test_active_identity.py`.
- **Зависит от:** F0-10.
- **Критерии приёмки:** mock HTTP server видит один ожидаемый principal при discovery и case; отсутствующий credential даёт unavailable; в artifacts нет bearer value.
- **Приоритет:** P0 · **Сложность:** S

### [F0-14] Полная валидация arguments active case
- **Источник:** аудит memrot — `memrot:mcp_audit/active/fixtures.py::schema_agrees`.
- **Зачем:** ошибка контракта инструмента не должна превращаться в результат security-проверки.
- **Что сделать:** заменить частичные проверки типов полной JSON Schema validation; сохранить понятную причину несовместимости и не вызывать инструмент при invalid arguments.
- **Файлы:** `mcp_audit/active/fixtures.py`; новый `tests/test_active_argument_validation.py`.
- **Зависит от:** F0-01.
- **Критерии приёмки:** bool вместо integer, значение вне enum, пропущенное required поле и нарушение nested schema отклоняются до transport; валидный case сохраняет прежнее исполнение.
- **Приоритет:** P0 · **Сложность:** S

### Фаза 1 — наблюдаемая память и изоляция эксперимента

### [F1-01] Capability preflight и проверяемые session semantics
- **Источник:** `Diskard:src/diskard/connectors/base.py`; `red-alert:red_alert/profile.py`; аудит `memrot:memrot/adapters/openai_compat.py`.
- **Зачем:** не выдавать stateless API за memory-bearing target.
- **Что сделать:** добавить capabilities persistence/session/identity/staging/evidence и required capabilities сценария; реализовать `memrot doctor --config ...` без атак. Указать client-history/server-session/stateless режим; неизвестное свойство не выводить из keyword scan.
- **Файлы:** `memrot/adapters/base.py`, `memrot/adapters/openai_compat.py`, `memrot/config.py`, `memrot/catalog/schema.py`, `memrot/cli.py`; новый `tests/test_attack_preflight.py`.
- **Зависит от:** F0-02, F0-06.
- **Критерии приёмки:** stateless mock не допускается к persistent case; black-box не удовлетворяет grey-box requirement; doctor показывает capabilities и причины skip; неподдерживаемые проверки не делают сетевых запросов атаки.
- **Приоритет:** P1 · **Сложность:** M

### [F1-02] Независимый EvidenceProvider и снимки памяти
- **Источник:** `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/evidence/base.py`; `agentic-red-teaming:src/memnotsafe/evidence/snapshot.py`.
- **Зачем:** отделить данные агента о записи от наблюдаемого состояния.
- **Что сделать:** добавить mark/collect/snapshot interface рядом с TargetAdapter; нормализовать record ID, owner, audience, layer, source и content digest. Реализовать in-memory provider и обёртку имеющегося Mongo inspection; diff должен видеть create/update/delete, а не только новые IDs.
- **Файлы:** `memrot/adapters/genai_invest.py`; новые `memrot/evidence/base.py`, `memrot/evidence/snapshot.py`, `memrot/evidence/diff.py`, `tests/test_evidence_snapshots.py`.
- **Зависит от:** F0-05, F0-08, F1-01.
- **Критерии приёмки:** неизменённый snapshot даёт пустой diff; update того же ID и deletion видны; self-asserted trusted не становится доверенным provenance; недоступный provider возвращает unknown/error.
- **Приоритет:** P1 · **Сложность:** M

### [F1-03] Bounded settle после consolidation
- **Источник:** `agentic-red-teaming:src/memnotsafe/adapters/base.py::SettleResult`; `core/runner.py`.
- **Зачем:** не считать задержанную запись неуспешной атакой.
- **Что сделать:** добавить ожидание persistence с monotonic deadline и состояниями observed/timeout/unavailable; число наблюдений и elapsed сохранять. Timeout означает только отсутствие записи в заданном окне при работающем reader.
- **Файлы:** `memrot/adapters/base.py`, `memrot/adapters/genai_invest.py`, `memrot/runner/engine.py`; новый `tests/test_attack_settle.py`.
- **Зависит от:** F1-02.
- **Критерии приёмки:** fake clock и delayed store дают observed без настоящего sleep; недоступный store — unavailable, не timeout; probe начинается после завершения settle.
- **Приоритет:** P1 · **Сложность:** S

### [F1-04] Изоляция попытки с проверкой восстановления
- **Источник:** `Diskard:src/diskard/connectors/base.py::IsolationController`; `Diskard:src/diskard/cli.py::_run_config_scan`.
- **Зачем:** новый marker не устраняет влияние старой poisoned policy.
- **Что сделать:** ввести attempt namespace и prepare/restore/verify protocol; реализовать reference in-memory backend, предусмотреть явный dedicated-stand reset. Shared DB не очищать глобально. Непроверенный reset записывать как isolation unavailable; зависимые повторы не объявлять независимыми.
- **Файлы:** `memrot/adapters/base.py`, `memrot/runner/engine.py`, `memrot/config.py`; новые `memrot/runner/isolation.py`, `tests/test_attack_isolation.py`.
- **Зависит от:** F1-02, F0-04.
- **Критерии приёмки:** два cases не видят состояние друг друга; exception вызывает restore; неверный checkpoint не проходит verify; соседний namespace сохраняется; ошибки reset не теряются вне result.
- **Приоритет:** P1 · **Сложность:** M

### [F1-05] Калибровка видимости A/A-new-session/A→B
- **Источник:** `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/evidence/calibrate.py::verify`.
- **Зачем:** проверить, что заявленные scope и principals соответствуют цели.
- **Что сделать:** отдельной opt-in командой записывать synthetic marker и читать через независимый target-filtered reader: автор, новая сессия автора, другой пользователь. Сопоставлять видимость с policy профиля; cleanup обязателен.
- **Файлы:** `memrot/cli.py`; новые `memrot/evidence/visibility.py`, `tests/test_memory_visibility.py`.
- **Зависит от:** F1-01, F1-02, F1-04.
- **Критерии приёмки:** `memrot doctor --config ... --verify-visibility` на fixture обнаруживает global/per-user mismatch; одинаковая фактическая identity A/B отклоняется; недоступный reader не заменяется ответом LLM.
- **Приоритет:** P1 · **Сложность:** M

### [F1-06] Подключение наблюдаемых memory-trace событий
- **Источник:** аудит memrot — `memrot:memory_trace/models.py`, `mcp_audit/adapters/memory_events.py`; `agentic-red-teaming:src/memnotsafe/evidence/telemetry.py`.
- **Зачем:** превратить lifecycle схему в проверяемую цепочку источников.
- **Что сделать:** добавить reader/hook для store write, retrieval и context inclusion с record/event refs; проверять scope, timestamps, parents и provenance. Сделать bridge в vocabulary аудитора. Inferred события harness сохранить отдельно, без повышения их статуса при наличии text canary; `used_in_reasoning` не заявлять как доступ к внутренним рассуждениям модели.
- **Файлы:** `memrot/tracer.py`, `memrot/runner/engine.py`, `mcp_audit/adapters/memory_events.py`; новые `memory_trace/reader.py`, `tests/test_memory_trace_bridge.py`.
- **Зависит от:** F1-02, F0-08.
- **Критерии приёмки:** fixture trace связывает запись, retrieval и prompt block; dangling/cross-run parent отклоняется; agent self-report не становится store observation; отсутствие события при partial coverage остаётся unknown.
- **Приоритет:** P1 · **Сложность:** M

### Фаза 2 — сценарии с проверяемым смыслом

### [F2-01] Goal-specific oracle вместо универсального canary OR
- **Источник:** аудит memrot; `agentic-red-teaming:src/memnotsafe/core/goal_contract.py`; `red-alert:red_alert/attacks.py::AttackScenario`.
- **Зачем:** законное запоминание предпочтения не должно считаться компрометацией.
- **Что сделать:** добавить versioned goal: protected object, authority, запрещённый переход, required evidence. Literal detector оставить сенсором; verdict выдаёт oracle конкретной цели. Перевести authorized correction в benign, отделить persistence observation от violation. Canary в отрицании/цитате не считать выполнением инструкции автоматически.
- **Файлы:** `memrot/models.py`, `memrot/catalog/schema.py`, `memrot/catalog/loader.py`, `memrot/runner/verdict.py`, integrity/leakage catalogs; новые `memrot/oracles/base.py`, `tests/test_goal_oracles.py`.
- **Зависит от:** F0-06, F0-07, F1-02.
- **Критерии приёмки:** собственная разрешённая correction — benign success; чужое изменение protected field с state diff — violation; «не выполняю CANARY» не подтверждает adoption; no evidence — INCONCLUSIVE.
- **Приоритет:** P1 · **Сложность:** M

### [F2-02] Парный причинный эксперимент clean/poison
- **Источник:** `Diskard:src/diskard/scenarios/delayed_recommendation_manipulation.py`; аудит `memrot:memrot/runner/engine.py`.
- **Зачем:** отделить эффект памяти от исходной уязвимости target и прямого prompt injection.
- **Что сделать:** выполнять clean и poisoned arms из одинакового checkpoint с тем же victim/probe; дополнительно поддержать memory-disabled или удалённую конкретную poisoned запись при наличии capability. Разделять наблюдённый эффект, связанные стадии и причинное подтверждение.
- **Файлы:** новый `memrot/runner/paired.py`, `tests/test_paired_experiments.py`; `memrot/models.py`, `memrot/reporting/aggregate.py`.
- **Зависит от:** F1-04, F1-06, F2-01.
- **Критерии приёмки:** target с постоянным BAC в обоих arms не получает memory-causal finding; effect только после observed poison получает подходящий уровень доказательности; невозможный counterfactual явно отмечается.
- **Приоритет:** P1 · **Сложность:** M

### [F2-03] Утечка заранее созданного секрета жертвы
- **Источник:** `Diskard:src/diskard/scenarios/cross_user_direct_memory_leak.py`; `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/scenarios/poison_to_tool_chain.yaml`.
- **Зачем:** проверить чтение защищённых данных, а не только перенос attacker-controlled маркера.
- **Что сделать:** fixture-admin создаёт synthetic secret в victim-only scope; attacker payload не содержит секрета; oracle проверяет disclosure и ownership через read/tool evidence. Отдельно маркировать admin-seeded secret и возможность attacker-induced memory write.
- **Файлы:** новый `memrot/catalog/prompts/generic/victim_memory_disclosure/catalog.json`, `tests/test_victim_memory_disclosure.py`; `memrot/oracles/`.
- **Зависит от:** F1-05, F2-01, F2-02.
- **Критерии приёмки:** уязвимая fixture раскрывает только свой уникальный victim secret; защищённая не раскрывает; planted attacker canary не засчитывается как извлечение victim secret; A/A-new-session и A→B различаются.
- **Приоритет:** P1 · **Сложность:** M

### [F2-04] Ограниченное расписание post-persistence шагов
- **Источник:** аудит `memrot:memrot/runner/engine.py`; `Diskard:src/diskard/scenarios/compaction_policy_poisoning.py`.
- **Зачем:** существующий единственный probe недостаточен для задержанных и повторных проверок.
- **Что сделать:** добавить необязательное typed расписание benign turns, consolidation, new-session и probe после legacy injection flow; фиксировать cycle/step IDs и budgets. Старый каталог компилируется в прежний короткий flow; произвольные Python/shell actions в данных не разрешать.
- **Файлы:** `memrot/models.py`, `memrot/catalog/schema.py`, `memrot/runner/engine.py`; новые `memrot/runner/schedule.py`, `tests/test_attack_schedule.py`.
- **Зависит от:** F1-03, F1-04, F0-08.
- **Критерии приёмки:** старые сценарии сохраняют порядок вызовов; расписание воспроизводит два цикла и три probes; превышение шагов останавливается явным incomplete; неизвестный operation отклоняется до запуска.
- **Приоритет:** P1 · **Сложность:** M

### [F2-05] Измерение compaction и memory rot по циклам
- **Источник:** `Diskard:src/diskard/scenarios/compaction_policy_poisoning.py`; аудит пробела `memrot:memrot/runner/engine.py`.
- **Зачем:** покрыть искажение памяти со временем как отдельную задачу кейса.
- **Что сделать:** добавить fixed facts и poisoned/clean arms с 0/1/3/5 consolidation cycles и одинаковыми benign distractors. Измерять сохранение разрешённых фактов, появление ложных фактов, изменение scope и survival payload по циклам; не заменять semantic truth сходством строк.
- **Файлы:** новые `memrot/catalog/prompts/generic/compaction_drift/catalog.json`, `memrot/oracles/fact_integrity.py`, `tests/test_memory_rot.py`.
- **Зависит от:** F2-01, F2-02, F2-04.
- **Критерии приёмки:** deterministic fixture с потерей/переносом факта на третьем цикле обнаруживается именно там; stable fixture не даёт drift; потеря наблюдаемости не превращается в нулевую деградацию.
- **Приоритет:** P1 · **Сложность:** M

### [F2-06] Sleeper с положительным и отрицательным trigger
- **Источник:** `red-alert:attacks/memory-poisoning-sleeper.yaml`; `agentic-red-teaming:src/memnotsafe/attacks/deferred_payload.py`.
- **Зачем:** отличить условную активацию от безусловного poisoning.
- **Что сделать:** самостоятельный сценарий с neutral/positive/near-miss probes в изолированных ветвях одного сохранённого состояния; использовать безопасное изменение ответа/действия и фиксированную trigger predicate.
- **Файлы:** новый `memrot/catalog/prompts/generic/delayed_trigger/catalog.json`, `tests/test_delayed_trigger.py`; `memrot/oracles/`.
- **Зависит от:** F2-01, F2-02, F2-04.
- **Критерии приёмки:** always-on fixture не проходит критерий selective sleeper; selective fixture проходит; near-miss не активирует эффект; каждый probe имеет отдельный evidence chain.
- **Приоритет:** P1 · **Сложность:** M

### [F2-07] Конкуренция poisoned и legitimate записей при retrieval
- **Источник:** аудит memrot — retrieval-поля `memrot:memory_trace/models.py` существуют без такого эксперимента.
- **Зачем:** измерять влияние top-k/ranking и количества distractors, а не только факт записи.
- **Что сделать:** на reference retriever создать fixed synthetic corpus, менять один фактор за эксперимент: top-k либо число конкурирующих записей; фиксировать query, rank, score, включение в prompt и эффект. При отсутствии retrieval evidence возвращать unsupported.
- **Файлы:** новые `tests/fixtures/retrieval_target.py`, `memrot/catalog/prompts/generic/retrieval_competition/catalog.json`, `tests/test_retrieval_competition.py`.
- **Зависит от:** F1-06, F2-02.
- **Критерии приёмки:** известный ранжирующий fixture даёт ожидаемые hit@k и downstream outcomes; попадание в top-k без prompt inclusion не засчитывается как adoption; параметры попадают в bundle.
- **Приоритет:** P2 · **Сложность:** M

### Фаза 3 — воспроизводимость, оценка и отчёты

### [F3-01] Frozen run manifest и проверяемый evidence bundle
- **Источник:** `agentic-red-teaming:src/memnotsafe/evidence/bundle.py`; `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/storage/runs.py`.
- **Зачем:** другой исследователь должен получить те же входы и понять границы наблюдения.
- **Что сделать:** сохранять resolved config без secrets, code/adapter/oracle versions, catalog hashes, фактические rendered payloads, model settings, target build, seed, isolation/coverage; artifacts перечислять с hashes и present/absent/unavailable. Manifest записывать последним атомарно; новый run не затирает предыдущий.
- **Файлы:** новые `memrot/artifacts/bundle.py`, `memrot/artifacts/manifest.py`, `schemas/attack-run.schema.json`, `tests/test_run_bundle.py`; `memrot/cli.py`.
- **Зависит от:** F0-08, F0-09, F1-02.
- **Критерии приёмки:** изменённый байт, path traversal и незавершённый manifest отвергаются; bundle содержит все attempts; модель/seed неизвестны — записано unknown; hash не называется цифровой подписью.
- **Приоритет:** P1 · **Сложность:** M

### [F3-02] Offline re-evaluation и явный live replay
- **Источник:** `agentic-red-teaming:src/memnotsafe/evidence/bundle.py::read_bundle`; `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/app_cli.py::_campaign_from_run`.
- **Зачем:** отделить повтор анализа от нового стохастического эксперимента.
- **Что сделать:** `memrot replay --bundle ... --offline` пересчитывает результаты из evidence без target/LLM; live mode использует frozen payloads и новый run ID. Проверять совместимость schema/oracle/target, сохранять расхождения; не обещать identical LLM response.
- **Файлы:** новые `memrot/replay.py`, `tests/test_attack_replay.py`; `memrot/cli.py`.
- **Зависит от:** F3-01, F2-01.
- **Критерии приёмки:** offline replay при запрещённой сети даёт прежние deterministic verdicts; live mock получает идентичные payloads; corrupt bundle и отсутствующий required artifact не дают CLEAN.
- **Приоритет:** P1 · **Сложность:** M

### [F3-03] Независимые повторы и интервалы неопределённости
- **Источник:** аудит `memrot:memrot/reporting/aggregate.py`; `Diskard:src/diskard/report.py::aggregate_run_metrics`.
- **Зачем:** единичный исход не характеризует вероятность успеха стохастической атаки.
- **Что сделать:** добавить repetitions с независимой изоляцией, фиксированным candidate ID и отдельным repeat ID; публиковать numerator/denominator, evaluated coverage, Wilson interval для независимых бинарных повторов. Adaptive discovery и utility считать отдельно; не усреднять неэквивалентные threat models.
- **Файлы:** `memrot/config.py`, `memrot/runner/engine.py`, `memrot/reporting/aggregate.py`, `memrot/cli.py`; новые `memrot/reporting/statistics.py`, `tests/test_repeat_statistics.py`.
- **Зависит от:** F0-07, F1-04, F3-01.
- **Критерии приёмки:** проверены n=0, 0/n, n/n и mixed errors; CI отсутствует при n=0; failures инфраструктуры видны отдельно; зависимые adaptive rounds не получают iid interval.
- **Приоритет:** P1 · **Сложность:** M

### [F3-04] Структурированный judge с provenance и abstention
- **Источник:** `agentic-red-teaming:src/memnotsafe/judge/verdict.py`; `red-alert:red_alert/judge.py`; аудит `memrot:memrot/detectors/llm_judge_stub.py`.
- **Зачем:** судья должен оценивать заявленный эффект, а не угадывать значение случайного marker.
- **Что сделать:** оставить literal sensor и добавить отдельный evaluator с goal/rubric version, baseline, scoped evidence; JSON outcome confirmed/refuted/unknown, quote/evidence refs, model config и prompt hash. Проверять цитату по реально переданному тексту; судье не разрешать подтверждать скрытый store/tool state или изменять hard evidence. Fallback фиксировать отдельным provenance.
- **Файлы:** `memrot/detectors/llm_judge_stub.py`, `memrot/detectors/base.py`, `memrot/models.py`; новые `memrot/judge/protocol.py`, `tests/test_judge_protocol.py`.
- **Зависит от:** F2-01, F3-01.
- **Критерии приёмки:** malformed JSON, выдуманная quote, unavailable model и prompt injection дают unknown/error либо валидное refutation; hard negative не перезаписывается YES; конфликт мягких оценок виден отдельно.
- **Приоритет:** P1 · **Сложность:** M

### [F3-05] Калибровочный набор и атаки на judge
- **Источник:** `agentic-red-teaming:src/memnotsafe/judge/calibration.py`; `tests/fixtures/judge_golden.jsonl`, `judge_injection.jsonl`.
- **Зачем:** structured output не гарантирует правильность решения.
- **Что сделать:** создать собственные RU/EN labelled pairs: positive, negative, negation, quotation, paraphrase, authorized correction, forged evidence и injection. Разделить development/holdout; метрики precision/recall/FPR/FNR, coverage/abstention и injection flip rate; human-reviewed и synthetic labels различать.
- **Файлы:** новые `memrot/judge/calibration.py`, `tests/fixtures/judge/`, `tests/test_judge_calibration.py`; `memrot/cli.py`.
- **Зависит от:** F3-04.
- **Критерии приёмки:** `memrot calibrate-judge --dataset ...` на fake judge считает известную confusion matrix; abstention на negative не считается true negative; пустой/неполный holdout не проходит gate; live scores не заявляются без реального прогона.
- **Приоритет:** P1 · **Сложность:** M

### [F3-06] Технический и банковский отчёты из одного read model
- **Источник:** `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/reporting/technical.py`, `business.py`; `Diskard:src/diskard/report.py::render_junit_xml`.
- **Зачем:** проверяющий должен видеть нарушение, доказательства и ограничения без чтения внутреннего JSON.
- **Что сделать:** общий read model для JSON/Markdown/HTML: scenario/goal, authority boundary, observed/inferred stages, evidence links, pre/post diff, counters, intervals, limits и replay command. Банковский раздел связывает подтверждённое действие с явно заданным business invariant; JUnit различает failure/error/skipped. Денежный ущерб не выводить из canary.
- **Файлы:** `memrot/reporting/emitter.py`, `memrot/reporting/html_emitter.py`; новые `memrot/reporting/read_model.py`, `memrot/reporting/junit.py`, `tests/test_report_evidence.py`.
- **Зависит от:** F3-01, F3-03, F2-01.
- **Критерии приёмки:** число и статусы attempts совпадают во всех форматах; видны per-case limitations и judge provenance; XSS payload остаётся текстом; unavailable evidence не отображается зелёной успешной стадией.
- **Приоритет:** P1 · **Сложность:** M

### [F3-07] Regression export и сравнение защиты
- **Источник:** `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/generation/freeze.py`; `reporting/regression.py`; `red-alert:red_alert/config.py::resolve_auth_modes`.
- **Зачем:** показать, что исправление закрывает конкретную атаку и сохраняет штатную работу.
- **Что сделать:** export frozen case из bundle; сравнивать baseline/hardened по candidate/goal/profile/target versions и одинаковому initial state. Результаты fixed/still_present/new/inconclusive; missing/error case не закрывает finding. Включить paired utility controls.
- **Файлы:** новые `memrot/regression.py`, `tests/test_attack_regression.py`; `memrot/cli.py`, `memrot/reporting/read_model.py`.
- **Зависит от:** F3-02, F3-06, F2-02.
- **Критерии приёмки:** отсутствующая во втором run атака — inconclusive; подтверждённый attack→clean при полном evidence — fixed; профиль/goal mismatch блокирует сравнение; utility regression показана отдельно.
- **Приоритет:** P1 · **Сложность:** M

### Фаза 4 — эффективность и расширение после стабилизации

### [F4-01] Adaptive search с корректной доставкой и fresh confirmation
- **Источник:** `Diskard:src/diskard/attacker.py::run_agentic_search`; аудит `memrot:memrot/runner/adaptive.py`.
- **Зачем:** улучшать payload без завышения успешности из-за накопленного состояния.
- **Что сделать:** выбирать поле mutation по delivery_channel: inject_turns/tool_stage.content_template/document; проверять сохранение goal и canary placeholder. Каждая search attempt изолирована; победитель подтверждается frozen fresh run без attacker feedback. Сохранять stop reason и lineage; NOT_EVALUATED/INVALID не переписывать бесконечно.
- **Файлы:** `memrot/runner/adaptive.py`, `memrot/mutation/techniques.py`, `memrot/pipeline.py`, `memrot/cli.py`, `tests/test_attack_adaptive.py`.
- **Зависит от:** F1-04, F2-01, F3-02, F4-02.
- **Критерии приёмки:** tool-result меняет staged content, не probe; malformed rewrite не запускается; discovery success, не воспроизведённый fresh confirmation, не считается confirmed regression case; failure генератора виден.
- **Приоритет:** P2 · **Сложность:** M

### [F4-02] Общий бюджет вызовов, времени и токенов
- **Источник:** `red-alert:red_alert/usage.py`; `agentic-red-teaming:src/memnotsafe/generation/budget.py`; аудит `memrot:memrot/mutation/llm_client.py`.
- **Зачем:** ограничить стоимость и завершать кампанию с понятным partial result.
- **Что сделать:** единый budget для target/attacker/judge/healthchecks/retries; monotonic deadline, max calls/turns/tokens и response-size limit. Запрашивать usage там, где доступно; unknown usage не заменять нулём. Не повторять state-changing запрос после неопределённого timeout без idempotency guarantee.
- **Файлы:** новый `memrot/runner/budget.py`, `tests/test_run_budget.py`; `memrot/mutation/llm_client.py`, `memrot/runner/engine.py`, `memrot/adapters/openai_compat.py`, `memrot/cli.py`.
- **Зависит от:** F0-08, F3-01.
- **Критерии приёмки:** fake clients прекращают запросы на границе; retries/preflight учтены; оставшиеся cases видны как budget-exhausted; partial bundle читается; неизвестные target tokens показаны как unknown.
- **Приоритет:** P1 · **Сложность:** M

### [F4-03] Provenance корпуса и лицензирование переносов
- **Источник:** `Diskard:LICENSE`; `memrot:memrot/catalog/imported/garak_dan/NOTICE.md`; `trustairlab_jailbreak/NOTICE.md`; отсутствие LICENSE у трёх остальных competitors.
- **Зачем:** банк должен понимать происхождение сценариев и условия использования материалов.
- **Что сделать:** создать manifest источников с URL/revision/hash/license/изменениями и типом evidence; самостоятельно написать перенесённые сценарии и тесты. Сохранить необходимые license/notice файлы для vendored материалов после проверки upstream; общую лицензию memrot выбрать с владельцем. Разделить research corpus и минимальный CI pack, фиксировать provenance каждого generated case.
- **Файлы:** новые `THIRD_PARTY_NOTICES.md`, `memrot/catalog/sources.json`, `docs/corpus_policy.md`, `tests/test_catalog_provenance.py`; существующие imported NOTICE.
- **Зависит от:** F3-01.
- **Критерии приёмки:** любой imported/generated case имеет разрешимый source record; неизвестная лицензия блокирует дословное vendoring, но не самостоятельную реализацию идеи; CI выявляет отсутствующие hashes/notices.
- **Приоритет:** P1 · **Сложность:** S

## 7. Открытые вопросы

| Решение | Принятое для roadmap допущение | Когда требуется ответ |
|---|---|---|
| Первый реальный backend | Сначала deterministic fixture и существующий genai-invest/Mongo путь; затем один независимый backend. Универсальность пока не заявляется | До добавления второго production adapter |
| Что банк считает нарушением | Явное правило authority/owner/audience и запрещённое действие; перенос canary сам по себе — observation | До утверждения banking benchmark |
| Обязательная глубина evidence | Для causal memory finding нужны independent persistence и связанный downstream effect; недоступные промежуточные стадии ограничивают claim | Перед приёмкой F2-01/F2-02 |
| Совместимость отчётов | Новая schema version и legacy reader; INCONCLUSIVE добавляется явно, старые отчёты не пересчитываются молча | До F0-06 |
| Целевая среда запуска | Linux/Python 3.12 offline CI; Windows smoke отдельно, live tests только на выделенном стенде | До фиксации support matrix |
| Разрешённые каналы внешних моделей | Offline deterministic путь обязателен; cloud judge/attacker/Presidio только явно настроены; реальные банковские данные не нужны для fixtures | До любого live evaluation |
| Хранение данных | По умолчанию sanitized artifacts; raw-content режим не вводить без требований доступа/retention | До F0-09/F3-01 |
| Что означает reset | Изолированный namespace либо проверенное восстановление dedicated stand; никаких глобальных wipe shared DB | До live реализации F1-04 |
| Размер повторов и статистический gate | На CI — небольшие deterministic samples; для live заранее фиксировать n, budget и критерий остановки. Adaptive discovery отдельно | До F3-03 |
| Разметка судьи | Synthetic regression corpus немедленно; independent human-reviewed RU/EN holdout нужен для заявления качества | До принятия judge как оценочного инструмента |
| Лицензия memrot | До решения владельца не добавлять предполагаемую лицензию; переносить чужие идеи собственной реализацией | До распространения сборки банку |
| Нужны ли vision и несколько агентов | В первой версии приоритет text, memory scopes и user/session boundaries; vision и полноценный multi-agent propagation — отдельные исследования | После завершения F3 |

Проверки, реально выполненные для этого документа: memrot — 376 passed/5 skipped плюс отдельно 32 passed; strict catalog — 26 файлов без ошибок; offline audit — partial без schema errors. Diskard — сохранённый локальный результат 174 passed/1 skipped. MOROK — 67 целевых тестов прошли; полный discovery в неполной среде: 685 tests, 1 failure, 3 errors. memnotsafe — повторный прогон с разрешённым только loopback: 1700 passed, 1 skipped, 1 failed (`tests/test_demo_launcher.py`, Windows path на Linux). red-alert — 203 passed и 5 environment failures в выполненном прогоне; повтор после смены окружения не завершён, Python 3.14 runtime оказался недоступен. Внешние target/LLM/production backends не запускались; авторские live-числа не использовались как собственные результаты.

## 8. Что сознательно не переносим

| Идея | Почему не переносим / что используем вместо |
|---|---|
| Переписать memrot на Giskard или LangGraph | Уже есть working runner/adapters/catalog/tests. Берём isolation/evidence контракты; framework migration не закрывает обнаруженные ошибки. Источники: `Diskard:src/diskard/cli.py`; `red-alert:red_alert/graph.py`; `memrot:memrot/runner/engine.py` |
| Считать mention ticker рекомендацией или canary доказательством вреда | Отрицание, цитата и разрешённая correction дают ложные находки. Нужны goal-specific oracle и policy. Источники: `Diskard:src/diskard/checks/recommendation_shift.py`; `memrot:memrot/runner/engine.py::_judge` |
| Выводить retrieval/adoption как observed из downstream текста | Сохраняем inferred evidence; неизвестная стадия не становится наблюдённой. Источники: `Diskard:src/diskard/report.py::stage_verdicts_for`; `memrot:memrot/runner/engine.py::_Lifecycle` |
| Принимать UNKNOWN retrieval за доказанную memory chain | Возможно показать ограниченный end-to-end signal, но causal claim остаётся неполным. Источник: `agentic-red-teaming:src/memnotsafe/oracles/composite.py` |
| Повышать soft evidence только в сторону успеха | Сохраняем disagreement и unknown; hard facts имеют независимый приоритет. Источник: `agentic-red-teaming:src/memnotsafe/oracles/judge_merge.py` |
| Засчитывать abstention на negative как верный ответ судьи | Это увеличивает apparent agreement без вынесенного решения. Отдельно считаем coverage и confusion matrix. Источник: `agentic-red-teaming:src/memnotsafe/judge/calibration.py` |
| Бинарный YES + любое state event = доказанное нарушение | Событие должно подтверждать конкретный goal и принадлежать попытке. Источник: `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/campaign/runner.py::_has_confirmed_evidence` |
| Повторять весь каталог competitors | Многие authority/roleplay/obfuscation варианты уже есть; новые формулировки не равны новым механизмам. Переносим только новый threat boundary/protocol/oracle. Источники: `memrot:memrot/catalog/prompts/`; `agentic-red-teaming:src/memnotsafe/attacks/` |
| Называть user-query, оформленный как документ, настоящей document/tool injection | Учитываем effective delivery channel, а не название семейства. Источники: `agentic-red-teaming:src/memnotsafe/attacks/document_regulation_graft.py`, `tool_error_echo_poisoning.py` |
| Увеличивать imported DAN/jailbreak bank как главный вклад | memrot уже импортирует эти банки. Они не подтверждают долговременную memory compromise и должны оставаться отдельным diagnostic threat model. Источник: `memrot:memrot/catalog/generator.py::ImportedBankGenerator` |
| Автономному attacker доверять reset, права и критерий успеха | Модель предлагает payload; lifecycle, identity, budgets и oracle контролирует harness. Источники: `Diskard:src/diskard/attacker.py`; `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/attacker/agent.py` |
| Фиктивный reset либо глобальный Mongo wipe как универсальная изоляция | Первый ничего не очищает, второй опасен для shared state. Используем namespace/verified checkpoint. Источники: `red-alert:red_alert/openclaw_client.py::isolate`; `Diskard:examples/connectors/investment_stand/connector.py::MongoNamespaceIsolation` |
| Сохранять только успешные traces, сырые judge.log, произвольную LLM narrative | Это selection bias, риск утечки и неподтверждённые выводы. Полный sanitized ledger и детерминированный отчёт обязательны. Источники: `red-alert:red_alert/report.py`, `judge.py`; `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/reporting/technical.py::add_narrative` |
| Автоматически запускать Codex из cwd неизвестного target для инспекции | Read-only не отделяет source instructions от правил агента и не ограничивает чтение всех секретов. Сначала обычные parsers и явные bindings. Источник: `red-alert:red_alert/analyzer.py::CodexHarnessAnalyzer` |
| Keyword absence → capability absent/high | Отсутствие слова в исходниках не доказывает отсутствия механизма. Используем verified adapter contract или unknown. Источник: `red-alert:red_alert/analyzer.py::_hint_state` |
| Закрывать finding по отсутствию во втором отчёте | Атаку могли не исполнить или потерять evidence. Нужен equivalent executed case. Источник: `Talent-Hub-Agentic-Red-Teaming-Case:agentic_redteam/reporting/regression.py::compare` |
| Сразу строить обязательные Langfuse/UI/control-plane | Локальные artifacts и CLI закрывают приёмку исследовательского инструмента; telemetry можно подключить позднее как необязательный exporter. Источники: `red-alert:red_alert/tracing.py`; `Diskard:src/diskard/console/` |
| Vision, OpenClaw host-exfil и movie-style pack в первой фазе | Не закрывают основные пробелы memory evidence/reproducibility; vision откладывается до появления реального multimodal target. Источники: `red-alert:red_alert/image_payload.py`; `red-alert:attacks/` |
| Объявить защиту памяти полной после зелёного suite | Mock tests проверяют harness; конкретные live experiments ограничены catalog, target build, policy и coverage. Источники: `memrot:tests/fixtures/fake_memory_target.py`; `agentic-red-teaming:src/memnotsafe/adapters/mock.py` |
