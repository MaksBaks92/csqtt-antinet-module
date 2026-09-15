# AntiNet Module System — внутренности и кроссплатформенный порт

Этот документ — для тех, кто **портирует AntiNet-сторону** модульной системы на другую платформу
(Desktop) ИЛИ **чинит/расширяет** её. Контракт, который обязан соблюдать сам модуль, — в
`MODULE_API.md`; здесь — **как AntiNet этот контракт исполняет**: какой компонент за что отвечает,
точные входы-выходы на каждой границе, и потоки коннект/пинг/хендовер/teardown, которые порт обязан
воспроизвести.

> Источник истины — Kotlin-код в репозитории AntiNet (`app/src/main/java/com/antinet/vpn/`; в
> авторский архив модуля он не входит — там только сторона МОДУЛЯ). Все имена ниже —
> реальные классы/методы; при расхождении верь коду. Порт = 1:1 зеркало этих потоков.

---

## 1. Компоненты AntiNet-стороны (кто за что отвечает)

| Компонент (файл) | Ответственность |
|---|---|
| **`module/ModuleManager.kt`** (object) | **Сердце.** Discovery модулей (скан `files/modules/<id>/module.json`) + ВЕСЬ lifecycle слот-процесса: `claim` слота из пула, `dlopen` скачанной `.so` через C-шим, ожидание маркера `ready`, кэш эндпоинта, watchdog смерти, рекавери на хендовере, teardown, heartbeat. **+ `installedModules()`** (дескрипторы для UI: имя/`version` из `module.json`/описание/схемы/updateUrl/homepage) **+ `checkUpdate(updateUrl)`** (GET JSON-манифеста → ModuleUpdate) **+ `installBundle`** (rollback-safe подмена каталога) **+ единый разбор маркеров живого stdout** (`forEachNewProgressLine` / Pascal `TailProgress`: `PROGRESS|`/`LOG|`/`ACTION_REQUIRED|`/`ACTION_CLOSE|`/`STATE_SAVE|`/`STATUS|`/`EVENT_ACK|`) — ОДИН парсер на оба читателя (стартовый poll + сессионный тейл). Платформо-СПЕЦИФИЧЕН (Android слот-`Service` + `bindService`; Desktop форкает процесс). |
| **`module/ModuleSlot.kt`** | Обёртка над одним слот-процессом (`android:process=":modN"`, 8 обезличенных слотов в манифесте — Android не даёт регистрировать процессы динамически). Повторяет ровно ту часть поверхности `java.lang.Process`, которой пользуется `ModuleManager` (`isAlive`/`kill`/`waitForDeath`) → вся супервизор-логика осталась структурно НЕТРОНУТОЙ при переезде с `ProcessBuilder` на слот. Один модуль на слот за всю жизнь процесса (два Go-рантайма в процессе дают `crosscall2`/SIGURG-конфликт). |
| **`module/ModuleListener.kt`** | Слушающий SOCKS5-сокет поднимает ХОСТ и передаёт слоту `ParcelFileDescriptor`'ом по тому же Binder-каналу (Desktop — наследованием fd, номер в `ANTINET_LISTEN_FD`; Windows — только `LISTEN_PORT`, сокет биндит сам модуль). Порт известен сразу и авторитетно; переживает смерть/подмену модуля (входящие копятся в backlog вместо `ECONNREFUSED`); `socks.port` выродился в маркер `ready`. |
| **`module/ModuleActionActivity.kt`** | UI интерактивного действия (§2.8) рисует ХОСТ: `confirm`/`form`/`choice`/`display`(+QR)/`webview`. У модуля нет APK, и UI нести негде. |
| **`module/ModuleProtocolHandler.kt`** | Мост «модуль ↔ реестр протоколов». ОДИН экземпляр на scheme. `parse` (ссылка→`VpnConfig`), `emit` (→`socks`-outbound поднятого модуля или `block`), `export`, `signatureParts`, `socksOutbound` (общий билдер socks-блока для connect И ping). Платформо-агностичен (кроме вызовов ModuleManager). |
| **`protocol/ProtocolRegistry`** | Реестр `ProtocolHandler`'ов. `registerDiscoveredModules(ctx)` (из `AntiNetApp.onCreate` + на смену пакетов) регистрирует `ModuleProtocolHandler` на каждую найденную scheme → парс/эмит/экспорт/дедуп идут единым швом, как для built-in протоколов. |
| **`models/Models.kt`** | `VpnConfig.ext["moduleLink"]` — непрозрачная ссылка. `isModuleBacked()` — признак module-конфига. `canBeCascade() = !isModuleBacked()` — модуль НЕ может быть каскадом (2-й хоп), но может быть основой. |
| **`service/VpnHealthMonitor.kt`** | Здоровье УЖЕ поднятой module-сессии. `probeVpnLiveness`/`probeAndRecoverPinned` берут потолок пробы через `ModuleManager.tunnelProbeBudgetMs` (модуль объявляет свою цену — общий потолок для built-in конфигов ему мал). На FAIL — двухуровневая эскалация: щадящий `signalLiveModuleIfSupported` (тот же event, что на хендовере), и только на исчерпание backoff'а — реальный relaunch. Гейт `moduleReportsUnrecoverableByNudge(scheme)` пропускает лестницу нуджей сразу к relaunch'у, когда модуль сам объявил `STATUS\|waiting`/`fatal` (§2.13) — по типизированному состоянию, с фоллбэком на разбор хвоста stdout для модулей без `STATUS\|`. |
| **`service/VpnTunnelLifecycle.kt`** | На connect-пути для `isModuleBacked()`: `ModuleManager.reconcileActiveHelper(scheme, link, verbose=true)` ДО генерации конфига (ep==null → abort+DISCONNECTED). `applyAppRouting` — с модели v3 (модуль = слот-процесс ТОГО ЖЕ пакета, что AntiNet) per-package TUN-исключение для модуля НЕ ГОДИТСЯ (слот включён в TUN как часть своего пакета, Husi-pattern-инвариант); egress модуля идёт мимо туннеля ЕДИНСТВЕННО через socket-level `protect()` (SCM_RIGHTS). `modulePkgs`-набор в `applyAppRouting` держится пустым намеренно, не как забытый мёртвый код. |
| **`tunnel/singbox/SingboxConfigGenerator.kt`** | `buildPrimaryMemberOutbound` → `handler.emit` (connect: socks поднятого модуля). `generateGroupPingConfig` → `ModuleProtocolHandler.socksOutbound` (ping: тот же socks-блок). |
| **`tunnel/singbox/SingboxTunnelModule.kt`** | `softReload` БЕЙЛИТ (`return false`) при смене конфига к/от/между module-конфигами (`config.id` сменился И одна из сторон `isModuleBacked()`) → оркестратор фолбэчит на полный `buildAndStartTunnel` → reconcile (своп не способен поднять helper нового конфига). Reload ТОГО ЖЕ module-конфига (DNS/стратегия/каскад) свопом ОК. |
| **`tunnel/TunnelManager.kt`** | `pingConfigsFastUrlTest` = wrapper над `pingBatchInternal`: partition на built-in/`parallelPing`-модули (ОДИН параллельный под-батч) и sequential-модули (ПО ОДНОМУ — свой helper); под-батчи сериализованы; `stopForPing` per-scheme в finally. |
| **`tunnel/singbox/DefaultNetworkMonitor.kt`** | На смене РЕАЛЬНОГО дефолт-интерфейса → `ModuleManager.onHandover()` (helper отд. процесс сигнала сети не получает — его надо рестартить). |
| **`service/AntiNetVpnService.kt`** | `finalizeDisconnectedState` → `ModuleManager.stopAll()` (session-end teardown ОБОИХ disconnect-путей — НЕ полагаться на `onDestroy`, его отменяет quick-reconnect). |
| **`tunnel/singbox/SingboxCoreHolder`** | `startModuleProtect(path)` / `stopModuleProtect()` (standalone protect-сервис) + `resetNetwork()` (расклин DNS после relaunch helper'а). |
| **libcore `module_protect.go`** (Go) | `StartModuleProtect(PlatformInterface, path)` / `StopModuleProtect()`: STANDALONE `protect.Service` (UNIX-сокет, SCM_RIGHTS-приёмник fd → `VpnService.protect` через `autoDetectInterfaceControl`), НЕ привязан к sing-box box'у (модуль стартует ДО него). |
| **`viewmodel/VpnViewModel.kt`** | Гарды каскада: `setCascadeConfig`/`addCascadeMemberToPool` отвергают module-конфиг (`!canBeCascade()` → toast). **+ state экрана «Модули»**: `installedModules`/`moduleUpdateStates` StateFlow + `refreshInstalledModules`/`checkModuleUpdate`/`checkAllModuleUpdates`. |
| **`ui/settings/ModulesScreen.kt`** | UI-карточка «Модули» (Настройки → Модули): список установленных модулей (имя · `version` из `module.json` · описание · схемы · ссылка) + авто-проверка обновлений (JSON-манифест `updateUrl`, сравнение `version` посегментно-числами) + ТИХАЯ установка бандла в `files/modules/<id>/` (ни установщика, ни промптов — модуль это файл, не APK). Платформо-СПЕЦИФИЧЕН (Compose UI). |

---

## 2. Границы вход-выход (точный I/O-контракт)

```
┌─ DISCOVERY ──────────────────────────────────────────────────────────────────┐
│ in : скан каталога модулей (Android `files/modules/<id>/module.json`;         │
│      Desktop `<exe>/modules/<id>/module.json`) — обе платформы одинаково       │
│ out: scheme → ModuleInfo(dir, helperBinary, parallelPing, handoverMode,        │
│                          hostEvents)                                           │
│      (ModuleManager.discover)                                                  │
└────────────────────────────────────────────────────────────────────────────┘
┌─ PARSE (импорт ссылки) ───────────────────────────────────────────────────────┐
│ in : raw "scheme://…"                                                          │
│ out: VpnConfig(name, protocol=scheme, server, port=0, ext["moduleLink"]=raw)   │
│      имя/сервер ← `helper summarize <link>` (parse-only сабкоманда, без        │
│      подъёма data-plane); #fragment перебивает (ModuleProtocolHandler.parse)   │
└────────────────────────────────────────────────────────────────────────────┘
┌─ CONFIG (хост передаёт СОДЕРЖИМЫМ перед стартом; на диск не пишется) ─────────┐
│ in : link + per-session SOCKS5 (user/pass/port=0)                              │
│ out: content = LISTEN_PORT/SOCKS_USER/SOCKS_PASS + LINK=<сырая ссылка>         │
│      (Android — C-строка через слот; Desktop — base64 в ANTINET_MODULE_CONFIG); │
│      helper САМОДЕКОДИТ LINK тем же парсером, что summarize/normalize          │
└────────────────────────────────────────────────────────────────────────────┘
┌─ HELPER (Android: dlopen в зарезервированный слот-процесс; Desktop: форк) ────┐
│ in : конфиг-содержимое (выше) + profileDir + protectPath — БЕЗ configPath      │
│ out: SOCKS5-листенер 127.0.0.1:<port>, сокет которого создал и передал ХОСТ;   │
│      порт известен хосту сразу; маркер `ready` (не файл socks.port с числом)   │
│ side: каждый исходящий fd → SCM_RIGHTS на protectPath (off-TUN bypass-mark)     │
│       PR_SET_PDEATHSIG=SIGKILL (Desktop; Android — lifecycle ведёт хост);      │
│       stdout → helper.stdout.log, НИКОГДА не недренируемый pipe (Android — хост │
│       отдаёт слоту путь, слот делает dup2 ДО dlopen, ModuleHostService.ERR_STDIO;│
│       Desktop — poUsePipes + TDrainThread, дренирует в тот же файл). Маркеры,    │
│       которые хост построчно ловит из этого файла:                              │
│       PROGRESS|/LOG|/ACTION_REQUIRED|/ACTION_CLOSE|/STATE_SAVE|/STATUS|/EVENT_ACK| │
│ in (обратный канал): Android — C-ABI antinet_module_event (приём доказывает rc);│
│       Desktop — построчный stdin (ACTION_RESULT|<id>|<payload>, handover), приём │
│       доказывает ответный EVENT_ACK| — трубе верить нельзя (§2.8)               │
└────────────────────────────────────────────────────────────────────────────┘
┌─ EMIT (генерация sing-box конфига) ───────────────────────────────────────────┐
│ in : VpnConfig + ModuleManager.cachedEndpoint(scheme, link)                    │
│ out: {"type":"socks","server":"127.0.0.1","server_port":port,                  │
│       "version":"5","username":user,"password":pass}                          │
│      модуль НЕ поднят → {"type":"block"} (АНТИ-УТЕЧКА, НЕ direct/null!)         │
│      (ModuleProtocolHandler.emit / .socksOutbound)                            │
└────────────────────────────────────────────────────────────────────────────┘
┌─ PROTECT (off-TUN) ───────────────────────────────────────────────────────────┐
│ helper fd ──SCM_RIGHTS──► protectPath ──► protect.Service ──► VpnService.protect│
│ ОДИН путь, без спецветок: fd приезжает через SCM_RIGHTS+adoptFd, т.е. он НАШ.   │
│ ⛔ Пина fd к физсети на data-path НЕТ: SELECT_NETWORK ПРИСВАИВАЕТ               │
│ protectedFromVpn = canProtect(...), т.е. вне окна владения VPN он СТИРАЕТ       │
│ bypass-метку → сокет уходит в наш же TUN (правило 12000 раньше 13000).          │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Потоки (что порт ОБЯЗАН воспроизвести)

### 3.1. Коннект
1. Оркестратор выбрал module-конфиг (`isModuleBacked()`).
2. `VpnTunnelLifecycle.buildAndStartTunnel` (на IO, ДО генерации конфига) → `ModuleManager.reconcileActiveHelper(scheme, link, verbose=true)`:
   - глушит ВСЕ live-helper'ы кроме нужной схемы (switch-away cleanup),
   - `ensureStarted(scheme, link, verbose=true)`: хост открывает и владеет SOCKS5-сокетом (`ModuleListener`) →
     собирает конфиг-содержимое (KEY=VALUE + сырая `LINK=`) → `SingboxCoreHolder.startModuleProtect(<noBackupFiles>/module_protect_path)` →
     Android — `dlopen`'ит скачанную `.so` в зарезервированный слот-процесс и передаёт слушающий сокет
     по Binder-каналу; Desktop — форкает `<helperBinary>`, передавая сокет наследованием fd
     (Windows — только номер зарезервированного порта, модуль биндит сам) → helper самодекодит `LINK`
     из переданного содержимого → poll маркера `ready` (≤95с) → `Endpoint(port,user,pass)`.
   - `ep==null` → abort + DISCONNECTED (НЕ продолжать с битым конфигом).
3. Config-gen: `handler.emit` → `socks`-outbound на `127.0.0.1:port` с per-session creds. Модуль off-TUN — ЕДИНСТВЕННО через socket-level protect (`applyAppRouting`'s `modulePkgs`-набор для модулей держится пустым намеренно — слот в том же пакете, что и хост, per-package исключение не годится, см. §4 инвариант 9).
4. sing-box поднят → трафик: app→TUN→sing-box→socks(127.0.0.1)→helper→протокол→exit.

### 3.2. Пинг
`TunnelManager.pingConfigsFastUrlTest`:
- **partition**: `mainConfigs` (built-in + `parallelPing`-модули) vs `moduleSeq` (sequential-модули, `protocol ∈ ModuleManager.sequentialPingSchemes()`).
- `moduleSeq` пуст → ранний `return pingBatchInternal(configs)` (обычный built-in путь, без модульной обвязки).
- иначе: `runSub(mainConfigs)` (ОДИН параллельный под-батч) → затем по ОДНОМУ `runSub([moduleCfg])` на каждый sequential (его pre-pass `ensureStarted(verbose=false)` поднимает/реюзит helper). Под-батчи сериализованы `pingMutex` (singleton `urlTestResultCallback` не коллизит); прогресс remap в общий `grandTotal`.
- **connection-safe**: пинг ТОГО ЖЕ link, что у активного коннекта → reuse живого helper'а; пинг СИБЛИНГА той же схемы с ДРУГИМ link при активном коннекте → ПРОПУСК (launch сиблинга убил бы коннект). `finally` → `stopForPing(scheme)` гасит ТОЛЬКО ping-helper'ы (re-проверка connect-during-ping).
- **почему sequential**: helper keyed by scheme (`live[scheme]`) → одной схемы live ТОЛЬКО ОДИН link; несколько одно-схемных в общий параллельный батч нельзя (живой socks у последнего → остальные -2). `parallelPing=true` декларирует, что схема выдержит несколько live-helper'ов → остаётся в параллельном батче.

### 3.3. Хендовер (смена сети)
`DefaultNetworkMonitor` (смена реального интерфейса) → `ModuleManager.onHandover()`:
- дебаунс `HANDOVER_DEBOUNCE_MS=2с` + коалесинг (флап WiFi↔моб = один рестарт) + СЕРИАЛИЗАЦИЯ (single-thread `handoverExec` → нет гонки за фиксированный порт).
- `recoverAllHelpers` → `restartOne` на каждый live: kill (`destroyForcibly`+`waitFor`) + `relaunchHelper` на ТОТ ЖЕ стабильный порт.
- после relaunch: `SingboxCoreHolder.resetNetwork()` (НЕ `reloadInstance` — порт стабилен, retarget не нужен; resetNetwork = `connectionManager.CloseAll()` + `Client.DrainInflight()` расклинивает DNS-петлю; ~µс).
- Дефолт (`handoverMode:"restart"`) — graceful in-place self-heal ОТВЕРГНУТ как общее правило (in-place reset обычно не достаёт резолверы на новой сети) — ТОЛЬКО fresh-процесс cold-restart (протокол-агностично).
- Opt-in `handoverMode:"signal"` — helper НЕ убивается, ему шлётся событие, дальше он чинит себя сам. **Уважают ОБЕ платформы**: Android — C-ABI `antinet_module_event(<причина>)` (не SIGUSR1: POSIX-сигналы в слот-процессе под ART недетерминированы), Desktop — построчный stdin (`SendHostEventToLive`, тот же канал, что у `ACTION_RESULT|…`; сигналы там не участвуют вовсе). Неуспех (процесс мёртв / событие не ПРИНЯТО) → fallback на cold-restart. Структура 1:1: Android `recoverAllHelpers`→`restartOne`→`notifyModule`; Desktop `RecoverAllHelpers`→`RestartOne`→`TrySignalHandover`→`NotifyModule`→`SendHostEventAcked` (щадящая ветка — та же функция, что зовёт health-монитор, одна реализация на оба вызывающих).
- **ПРИЧИНА события — часть контракта (`hostEvents`, MODULE_API §2.8).** Их четыре: `handover` (сеть сменилась), `netlost` (годной сети нет), `netback` (появилась снова), `stall` (сеть та же, но проба хоста через модуль не прошла). Дескриптор перечисляет те, что модуль РАЗБИРАЕТ; `handover` парсер добавляет всегда. Подмена необъявленной причины — одна дверь на платформу (`wireCause` / `WireCause`): `stall` → `handover` (health-нудж и раньше приходил этой строкой), `netlost`/`netback` → не шлются вовсе (их у хоста раньше не было, а `handover` вместо них — ложь про смену сети), `stop`/`ACTION_RESULT|…` — не причины и идут как есть. Инвариант: старый модуль на новом хосте получает ровно то же, что получал раньше, а новый модуль на старом хосте — только `handover`, поэтому причины обязаны быть оптимизацией, а не условием работы.
- Источник `netlost`/`netback` — тот же владелец дефолтной сети, что и у хендовера (Android `DefaultNetworkMonitor.setDefaultNetwork`, Desktop `TNetworkPoller.CheckModuleHandover`), и адресуются они И стартующим сессиям: именно в окне подъёма модуль жжёт свой стартовый бюджет.
- **«Принято» ≠ «записано».** Android читает rc C-ABI-вызова (`-2` = обработчика нет). У Desktop канал однонаправленный, поэтому модуль обязан ответить `EVENT_ACK|<event>` в stdout, а `NotifyModuleEvent` ждёт его до 2.5с (полтора цикла сессионного тейла, который и разбирает маркер — второго читателя `helper.stdout.log` не заводится). Без ack модуль, объявивший `"signal"` и не читающий stdin, отменял бы себе cold-restart и оставался с протухшими сокетами. §2.8 MODULE_API.md.

### 3.4. Teardown
- **disconnect** → `AntiNetVpnService.finalizeDisconnectedState` → `ModuleManager.stopAll()` (инкремент `stopGeneration` + kill всех helper'ов + `stopModuleProtect`). Именно `finalizeDisconnectedState` (session-end ОБОИХ disconnect-путей), НЕ `onDestroy` (quick-reconnect его отменяет → helper-зомби).
- **конец пинга** → `stopForPing(scheme)` per-scheme (helper + shared protect, если `live` опустел).
- **anti-zombie**: `ensureStarted` ловит `stopGeneration` сменившийся за время блокирующего cold-test (~36с) → НЕ добавляет helper в `live` + `destroyForcibly` (узкий race connect-cold-test vs disconnect).

### 3.5. Смена сервера (switch to/from/between module)
- `SingboxTunnelModule.softReload`: `config.id` сменился И (`config.isModuleBacked()` ИЛИ `connected.isModuleBacked()`) → `return false` → оркестратор → `buildAndStartTunnel` → `reconcileActiveHelper(newScheme, newLink)`:
  - module→другой module (другая схема) / module→non-module → глушит старый helper (иначе зомби);
  - same-scheme другой link → `ensureStarted` сам evict'ит старый;
  - non-module → `scheme=null` → глушит ВСЕ helper'ы.
- Reload ТОГО ЖЕ module-конфига (DNS/стратегия/каскад-тоггл) — свопом ОК (helper жив, кэш валиден).

### 3.6. Watchdog смерти helper'а
`startWatcher` (поток на `process.waitFor()`) → на смерть `superviseDeath` (на `handoverExec`, сериализован):
- остановлен/заменён → не воскрешать; иначе `relaunchHelper` на тот же порт (3 ретрая) + новый watcher + `resetNetwork`.
- crash-loop-guard: `crashLoopMaxDeaths` (default 5) быстрых (короче `crashLoopWindowSec`, default 15с, аптайма) смертей подряд → **backoff + ре-арм** (`scheduleRearm`, лестница 30→60→120→300с, эскалация по раунду, cap), а НЕ отказ навсегда: причина крэш-петли обычно временная (сеть/сервер), и при её уходе helper поднимается сам, без ручного реконнекта. Оба порога — module-декларируемые с per-module override (§2.10 MODULE_API.md).

---

## 4. Инварианты (НЕ ЛОМАТЬ при порте/правках)

1. **Слушающий SOCKS5-сокет создаёт и передаёт ХОСТ**, не модуль (Android — Binder/`ParcelFileDescriptor`; Desktop Unix — наследование fd; Desktop Windows — хост резервирует номер порта, модуль сам биндит именно его). Порт известен хосту сразу и переживает смерть/подмену модуля.
2. **helper: `PR_SET_PDEATHSIG=SIGKILL`** (Desktop — форкнутый процесс; Android — lifecycle ведёт хост-слот, отдельного PDEATHSIG не требуется) — умереть с родителем (нет орфана).
3. **Стабильный порт на relaunch** (reuse) → outbound НЕ retarget'ится → `resetNetwork` (не дорогой `reloadInstance`) достаточен.
4. **Декод ссылки — в Go-helper'е** (сабкоманды `summarize`/`normalize` + самодекод `LINK` на коннекте; НИКАКОГО Kotlin `SubprocessEntry` — контракт v2). Сабкоманды pure-parse (без Go-рантайма data-plane).
5. **helper stdout → ФАЙЛ** (`Redirect.to`), НЕ недренируемый pipe (иначе data-plane виснет на переполнении pipe-буфера).
6. **emit при не-поднятом модуле = `block`** (анти-утечка), НЕ `direct`/`null` (direct-fallback = трафик мимо VPN, реальный IP).
7. **Module-конфиг НЕ каскад** (`canBeCascade()=false`): socks локален (`127.0.0.1`), как удалённый 2-й хоп недостижим. Основой (primary) — может.
8. **Module-switch — через `buildAndStartTunnel`+reconcile**, НЕ свопом (своп не поднимет helper нового конфига → битый block + зомби).
9. **Модуль off-TUN — ТОЛЬКО через socket-level protect (SCM_RIGHTS)**, не через package-level TUN-исключение. С модели v3 (модуль = слот-процесс/downloaded-файл в ТОМ ЖЕ пакете, что хост) `addDisallowedApplication`-подобный механизм для модуля не работает в принципе (весь пакет включён в TUN) — если protect не сработал, egress модуля петлял бы через собственный туннель.
10. **teardown сессионных ресурсов — в `finalizeDisconnectedState`**, не `onDestroy` (quick-reconnect отменяет onDestroy).

---

## 5. Кроссплатформенный порт (что переиспользуется, что переписать)

**Контракт и helper платформо-АГНОСТИЧНЫ** — переиспользуются как есть:
- сам **helper-бинарь** (Go): парсинг конфига (KEY=VALUE+`LINK=`) + SOCKS5 + protect-fd-IPC — платформо-агностичны; платформо-специфичен ТОЛЬКО механизм доставки содержимого (Desktop — `ANTINET_MODULE_CONFIG` env-var, argv-путь — легаси-фоллбэк; Android — C-строка параметром C-ABI-вызова, argv не участвует вовсе). Один Go-исходник, разные build-таргеты.
- **сабкоманды декода `helper`'а** (`summarize`/`normalize` + самодекод `LINK` на коннекте): чистый парсинг ВНУТРИ Go-бинаря → переносится КАК ЕСТЬ (на Desktop ТОТ ЖЕ бинарь, JVM-glue не нужен).
- **SOCKS5-chaining**: sing-box-сторона цепляет `socks`-outbound на `127.0.0.1:port` — идентично на любой платформе.

**Платформо-СПЕЦИФИЧНА только обёртка** (`ModuleManager` + protect) — переписать на Desktop:

| Что | Android | Desktop-порт (уже реализовано) |
|---|---|---|
| **Discovery** | скан каталога `files/modules/<id>/module.json` | скан каталога `<exe>/modules/<id>/module.json` (те же ключи schemes/helperBinary/parallelPing/handoverMode/hostEvents + сгенерированный `bundleTarget`; `build.py` генерит этот dist-`module.json` из дескриптора) |
| **Запуск helper'а** | `dlopen` скачанной `.so` (`c-shared`) в зарезервированный слот-процесс (`:mod0`..`:mod7`) через C-шим | `exec` бинаря из каталога установки модуля (форк; нативка грузится свободно — W^X не мешает) |
| **Off-TUN (protect)** | SCM_RIGHTS UNIX-сокет → `VpnService.protect` — ЕДИНСТВЕННЫЙ механизм (с модели v3 package-level TUN-исключение для модуля НЕ годится — слот в том же пакете/UID, что хост) | канон-инъекция `shared/offtun`: `SO_BINDTODEVICE`/`IP_UNICAST_IF`/`IP_BOUND_IF` — bind сокета helper'а к физическому интерфейсу, независимо от routing/hijack/состояния туннеля |
| **Handover-сигнал** | `DefaultNetworkMonitor` → C-ABI `antinet_module_event` (не SIGUSR1 — доставка сигнала в слот-процессе под ART недетерминирована) | Desktop-мониторинг смены дефолт-сети → `OnHandover()`; `handoverMode="signal"` → построчный stdin-event (`SendHostEventToLive`), иначе и на неуспех → kill (relaunch делает watcher) |
| **Пропажа/возврат сети** | `DefaultNetworkMonitor.setDefaultNetwork` (единственный писатель дефолтной сети) → `ModuleManager.onNetworkAvailability` → причина `netlost`/`netback` живым И стартующим (`launchingSlots`) | `TNetworkPoller.CheckModuleHandover` (там же, где читается fingerprint адаптера) → `ModuleManager.OnNetworkAvailability` → `TModuleNetEventThread` → те же причины живым и стартующим (`GLaunchProcs`) |
| **stopAll на disconnect** | `finalizeDisconnectedState` | session-end хук Desktop-демона |

**Чеклист Desktop-порта `ModuleManager`-эквивалента** (1:1 потоки §3):
1. discover: скан каталога модулей → `(scheme→helperBinary/entry/parallelPing)`.
2. ensureStarted: собрать конфиг-содержимое (KEY=VALUE + сырая `LINK=`, БЕЗ записи на диск) + resolvers → создать и передать SOCKS5-сокет (хост владеет им, порт известен сразу) → старт protect-IPC → запустить helper с содержимым (helper самодекодит `LINK`) → poll маркера `ready` → endpoint.
3. emit: `socks`-outbound на `127.0.0.1:port` (или `block`).
4. watchdog смерти + relaunch на тот же порт + resetNetwork.
5. onHandover: kill+cold-relaunch (дебаунс+коалесинг+сериализация).
6. teardown: stopAll на disconnect, stopForPing на конце пинга.
7. exclude egress helper'а из TUN.
8. ВСЕ инварианты §4 (стабильный порт, block-fallback, не-каскад, switch-через-rebuild).
9. (опц., UI) карточка «Модули»: список установленных (имя/версия/описание/ссылка) + авто-проверка обновлений по JSON-манифесту (сравнение `version` посегментно-числами) + ТИХАЯ установка бандла в каталог модуля. Версия — `version` из `module.json` (единственная; парного `versionCode` в контракте нет).

> Пиши модуль и helper так, чтобы они НЕ знали платформу — тогда твой модуль заработает и на
> Desktop-порте без изменений (поменяется только обёртка на стороне клиента).
