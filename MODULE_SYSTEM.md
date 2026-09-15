<!-- Копия module_system/README.md из репозитория AntiNet. Пути приведены к раскладке
     этого архива: префикс корня архива в нём отсутствует. -->

# AntiNet Module System

Здесь живёт **ВСЁ про модульную систему AntiNet** — механизм добавлять поддержку новых
wire-протоколов (VPN/прокси/туннелей), data-plane которых НЕ вкомпилен в AntiNet, **без
пересборки самого приложения**. Модуль — это **скачиваемый файл** (на Android — `.so`
`-buildmode=c-shared`, на Desktop — исполняемый файл), НЕ приложение и НЕ APK. AntiNet сканирует
свой каталог модулей, поднимает найденный артефакт в отдельном процессе (Android —
зарезервированный слот-процесс, `dlopen`; Desktop — форк) и гонит трафик через локальный SOCKS5,
слушающий сокет для которого создаёт САМ хост. **AntiNet протокол-агностичен** — знает только
контракт (этот каталог) + SOCKS5, ничего про конкретный протокол.

```
AntiNet (sing-box)  ──SOCKS5──►  helper модуля (Android: dlopen в слот; Desktop: форк)  ──proto──►  интернет
                                  под UID AntiNet · freeze-immune · off-TUN (protect-fd)
```

**Декод формата ссылки — полностью в Go-helper'е** (сабкоманды `summarize`/`normalize` + самодекод
конфига на коннекте). Kotlin/JVM-glue НЕТ ни на одной платформе → один и тот же модуль работает и на
Android, и на Desktop-порте. (`apiVersion: 1` — единственная выпущенная версия контракта; «v2»/«v3»
в истории разработки были ВНУТРЕННИМИ итерациями, наружу не публиковались, см. MODULE_API.md §6
«Версионирование».)

---

## Из чего состоит модуль (раскладка каталога)

Чёткое разграничение — **что правишь, что описываешь, чем собираешь, куда падают билды**:

| Зона | Путь | Что это |
|---|---|---|
| **Описание** | `module.json` | ЕДИНЫЙ дескриптор-источник: schemes/name/description/homepage/updateUrl/version/handoverMode/hostEvents/parallelPing + helperBinary{android,desktop} + build{}. Из него `build.py` ГЕНЕРИТ dist-`module.json` для обеих платформ — **описание не дублируется**; в каждый бандл сборщик дописывает `bundleTarget` (подпись арки, §2.5 MODULE_API). Прежние ключи `android{applicationId,service}`/`build.gradleProject` УДАЛЕНЫ (Ф7, APK-модель ушла). |
| **Go (правишь)** | `native/` | data-plane helper'а (свой протокол) + `go.mod`. Свой код (echo) — в репо; вендорный (qwdtt/masterdns) = upstream-клон (gitignored) + трекаемый `antinet-*.patch`. |
| **Билды (выход)** | `dist/` | `build.py` кладёт сюда ВСЮ выдачу: `dist/android/<abi>/lib*.so` (`-buildmode=c-shared`, скачиваемый файл — НЕ упакован ни в какой APK) + `dist/desktop/<os>_<arch>/<bin>[.exe]` + `module.json` рядом с каждым. **Gitignored** (артефакты). |

---

## Карта папки корня архива

| Путь | Что это | Кому |
|---|---|---|
| **`MODULE_API.md`** | **Контракт** — что модуль обязан предоставить (`module.json`, Go-helper + сабкоманды). Входы-выходы, семантика каждого ключа. | Разработчику модуля |
| **`PORTING.md`** | **Внутренности AntiNet-стороны** — какой компонент за что отвечает + потоки коннект/пинг/хендовер/teardown + **кроссплатформенный порт**. | Тому, кто портирует/чинит/расширяет AntiNet-сторону |
| **`build.py`** | **Единый сборщик** helper'а под любую ОС (android `.so` `c-shared` / windows-linux-darwin) из дескриптора. Генерит dist-`module.json`. | Обоим |
| **`tools/build-module.py`** | Низкоуровневый android-only билдер (NDK clang → `-buildmode=c-shared` `.so`). Зовётся из `build.py`. | Редко напрямую |
| **`examples/moduleecho/`** | **Полный образец** (passthrough): обязательная обвязка + ВСЕ опц.-фичи (interactive action, normalize, PROGRESS, карточка) — demo помечено `// DEMO`/гейтится. **Копируй как скелет, лишнее убери.** | Разработчику модуля |
| **`(репозиторий AntiNet) examples/modulemasterdns/`** | **Реальный модуль** — MasterDnsVPN / StormDNS (DNS-туннель): вендорный Go-движок в `native/` + патч. | Референс «по-настоящему» |
| **`(репозиторий AntiNet) examples/moduleqwdtt/`** | **Реальный модуль** — qWDTT (WireGuard-over-TURN через VK-звонки): вендорный go_client + netstack/SOCKS-обвязка патчем. | Референс вендоринга |
| **`shared/`** | **Каноны** — код, который у всех модулей ОБЯЗАН быть один. ВСЕГДА: `lifecycle` (PDEATHSIG, oom_score_adj, приём событий хоста, маркер `ready`), `protect` + `offtun` (SCM_RIGHTS-клиент и off-TUN bind, плюс обе формы protect-адаптера), `hostproto` (весь протокол разговора с хостом), `entry` (точки входа обеих платформ). По флагу дескриптора: `socks5` (`"socks5": true` — весь SOCKS5-протокол) и `dns` (`"dnsResolver": true` — protected off-tunnel резолвер dial-целей). `build.py` копирует их в main-пакет helper'а ПЕРЕД сборкой и удаляет после: в дереве модуля их нет и быть не должно. | Разработчику модуля |

---

## Тулчейн: что нужно установить

`--doctor` проверяет хост и печатает, чего не хватает и командой что поставить:

```bash
python build.py --doctor --os all --module echo
```

**Три РАЗНЫХ требования — путать их не надо, на этом чаще всего и застревают:**

| Что собираем | Чем | Кросс-компиляция |
|---|---|---|
| **desktop-helper** (`windows`/`linux`/`darwin`) | **только Go** (версию см. ниже) | **да, с любого хоста на любую ОС.** `CGO_ENABLED=0` — C-тулчейн не нужен вообще. Собрать Linux-бинарь на Windows и наоборот можно одной командой |
| **android-helper** (`.so`, `-buildmode=c-shared`) | Go + **Android NDK** (clang из него) | **да, с любого хоста.** Ни Gradle, ни Android SDK, ни AGP: модуль — файл, а не приложение |
| ~~`actionBinary`~~ — **ЛЕГАСИ, новым модулям не нужен** | cgo → C-тулчейн целевой ОС | **нет.** См. врезку ниже — тебе это поле объявлять НЕ надо |

### Go

Минимум задаёт **`go`-директива в `go.mod` собираемого модуля**, а не эта страница: у образца echo
это `go 1.25.0`. `build.py --doctor` читает go.mod и сверяет с установленной версией — отдельного
числа, которое разъедется с go.mod, здесь намеренно нет.

| Хост | Команда |
|---|---|
| Windows | `winget install --id GoLang.Go -e` (или MSI/ZIP с https://go.dev/dl/) |
| Linux | `sudo apt install golang-go` (Debian/Ubuntu) либо tarball с https://go.dev/dl/ в `/usr/local` |
| macOS | `brew install go` (или PKG с https://go.dev/dl/) |

### Android NDK (нужен ТОЛЬКО для `--os android`)

Ищется в таком порядке: `ANDROID_NDK_HOME` → `ANDROID_NDK_ROOT` → `ANDROID_HOME/ndk/<последняя версия>` → `ANDROID_HOME/ndk-bundle`. Путь можно передать и явно — `tools/build-module.py --ndk <path>`.

| Хост | Как поставить и что прописать |
|---|---|
| Windows | Android Studio → SDK Manager → SDK Tools → **NDK (Side by side)**; либо `sdkmanager "ndk;27.2.12479018"`; либо ZIP с https://developer.android.com/ndk/downloads.<br>Затем: `setx ANDROID_NDK_HOME "C:\Android\Sdk\ndk\27.2.12479018"` |
| Linux | `sdkmanager "ndk;27.2.12479018"` либо ZIP оттуда же.<br>Затем: `export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.2.12479018` |
| macOS | то же; `export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/27.2.12479018` |

Android API level по умолчанию — 26 (`--api`), ABI по умолчанию — `arm64-v8a` (`--abis arm64-v8a,armeabi-v7a,x86_64`, `all` = все четыре).

### ⛔ C-тулчейн модулю НЕ нужен. `actionBinary` — легаси

**UI рисует КЛИЕНТ, а не автор модуля** — это правило контракта (§2.5/§2.7), а не пожелание.
Модуль присылает **декларативное правило** строкой `ACTION_REQUIRED|<id>|<payloadB64>`, а рисует его
хост: Android — `ModuleActionActivity`, Desktop — `antinet-action`, поставляемый ВМЕСТЕ С КЛИЕНТОМ и
форкаемый для ЛЮБОГО модуля. **От модуля не требуется ни строчки UI-кода и ни одного C-компилятора.**

Поле `module.json: actionBinary` — пережиток модели, где своего рендерера у хоста не было и автор
был обязан собирать cgo+webkit-бинарь под каждую desktop-ОС ради UI, к его протоколу отношения не
имеющего. Сейчас:

- на **Android** поле не читается ВООБЩЕ (хост его не знает — рисует сам);
- на **Desktop** хостовый рендерер (`HostActionRendererPaths`) пробуется ПЕРВЫМ, бинарь модуля —
  только фоллбэк для сторонних модулей, опубликованных до появления рендерера;
- фоллбэк этот к тому же почти бесполезен: и хостовый рендерер, и модульные бинари тянут ОДИН И ТОТ
  ЖЕ `webview_go` одной и той же версии — если у хостового не хватает WebView2/webkit2gtk, у
  модульного не хватит их ровно так же.

**Ни один из трёх примеров (`echo`, `masterdns`, `qwdtt`) `actionBinary` не объявляет** — эталон
обязан показывать контракт, а не исключение из него: автор копирует `echo` и наследует всё, что в
нём лежит.

Если ты всё же пишешь свой рендерер (не рекомендуется — ты берёшь на себя UI, который хост уже
умеет), тебе понадобится C-тулчейн ЦЕЛЕВОЙ ОС: Windows — MSYS2 + `mingw-w64-x86_64-gcc`; Linux —
`build-essential libgtk-3-dev libwebkit2gtk-4.1-dev`; macOS — `xcode-select --install`.

---

## Быстрый старт (новый модуль за 5 шагов)

```bash
# 1. Скопировать образец-template
cp -r examples/moduleecho examples/mymod

# 2. Отредактировать ДЕСКРИПТОР (единый источник):  examples/mymod/module.json
#    schemes / name / description / version / helperBinary{android:"libmymod.so", desktop:"mymod-helper"} /
#    build{goDir, goPkg, ldflags}
#    → build.py сгенерит из него dist-дескриптор (НЕ редактируй его руками).
#    ⚠ Ключей `android{applicationId, service}` и `build.gradleProject` в дескрипторе НЕТ —
#    объявлять их не надо: модулю нужны только Go и NDK, Gradle он не использует.

# 3. native/.../cmd/helper/main.go — заменить ТЕЛО dial'а (passthrough) на свой протокол.
#    SOCKS5-фронт (хостовый сокет) + protect-fd + PDEATHSIG + сабкоманды summarize/normalize — оставить.

# 4. Собрать helper под Android + (опц.) desktop-ОС:
python build.py --os android --module mymod --abis arm64-v8a
#    → helper `.so` (c-shared) + module.json в examples/mymod/dist/android/<abi>/
python build.py --os windows --module mymod   # опционально, desktop-порт

# 5. Разложить модуль в каталог модулей AntiNet (Android — files/modules/<id>/,
#    Desktop — <exe>/modules/<id>/) — либо тихой установкой бандла из карточки «Модули»
#    (см. §2.5 MODULE_API.md), либо вручную для локальной отладки.
# Импортировать ссылку mymod://... в AntiNet → коннект/пинг идут через модуль.
```

Подробности каждого шага и точные сигнатуры — в `MODULE_API.md`.

---

## Контракт в одной таблице (входы-выходы)

| Граница | Вход | Выход |
|---|---|---|
| **Discovery** | скан каталога модулей (`<antinet>/modules/<id>/module.json`, обе платформы) | AntiNet знает scheme→(каталог, helperBinary, parallelPing, handoverMode, hostEvents) |
| **`helper summarize <link>`** | непрозрачная ссылка | 2 строки `name`\n`server` для карточки конфига |
| **`helper normalize <raw>`** (опц.) | произвольный текст (JSON/base64-конфиг) | 1 строка канон-`scheme://`-link (или пусто) |
| **`helper canping <link>\n<stateDir>\n<blob>`** (опц.) | ссылка + каталог состояния + сохранённый блоб (3 строки через `\n`) | «могу подняться без интерактива?»: `ok`/`true`/`1`/`yes` = да, ЛЮБОЙ другой ответ и молчание = нет (fail-closed). Спрашивается ТОЛЬКО при `pingNeedsConsent:true` (§2.10) |
| **helper, коннект** | конфиг-содержимое (Android — C-строка через слот; Desktop — argv/`ANTINET_MODULE_CONFIG`): KEY=VALUE + сырая `LINK=` | SOCKS5-листенер на `127.0.0.1` (сокет создаёт и передаёт ХОСТ) + маркер `ready` + protect-fd через `protectPath` |
| **helper, живой stdout** | — | построчные маркеры: `PROGRESS|`/`LOG|` (юзеру), `ACTION_REQUIRED|`/`ACTION_CLOSE|` (интерактив, §2.7), `STATE_SAVE|` (блоб состояния, §4), `STATUS|` (типизированное состояние → решения хоста, §2.13), `EVENT_ACK|` (подтверждение приёма события хоста, §2.8) |
| **helper, входящие события** | Android — C-ABI `antinet_module_event`; Desktop — построчный `stdin` (`handover`, `ACTION_RESULT|<id>|<payload>`) | реакция модуля + обязательный `EVENT_ACK|<event>` (иначе десктопный хост считает событие недоставленным и делает cold-restart) |
| **emit (AntiNet)** | `VpnConfig` поднятого модуля | `socks`-outbound JSON на `127.0.0.1:port` (или `block`, если не поднят) |

`config` (коннект-путь) ЕДИН на обеих платформах: хост пишет `LISTEN_PORT`/`SOCKS_USER`/`SOCKS_PASS` +
сырую `LINK=`, а helper **самодекодит** ссылку тем же парсером, что `summarize`/`normalize`.

---

## Кому что читать

- **Пишешь модуль** → начни с `MODULE_API.md`, скопируй `examples/moduleecho/` как скелет, гляди в
  `(репозиторий AntiNet) examples/modulemasterdns/` как на «по-настоящему».
- **Портируешь AntiNet на другую платформу / чинишь-расширяешь модуль-слой** → `PORTING.md`.

---

## Раздача автору + публикация

**Самодостаточный архив для автора** (исходники + сборочная система + доки; собирается БЕЗ репозитория AntiNet):
```bash
python build.py --package --module qwdtt   # → dist-archive/qwdtt-module-v<ver>.zip
```
Внутри:

| В архиве | Что |
|---|---|
| `README.md` | точка входа автора (генерится под конкретный модуль) |
| `MODULE_SYSTEM.md` | копия ЭТОГО файла — обзор + **тулчейн** + карта папок. Пути в ней автоматически приводятся к раскладке архива (префикса корня архива там нет) |
| `MODULE_API.md`, `PORTING.md` | контракт и внутренности AntiNet-стороны |
| `build.py`, `tools/build-module.py` | сборочная система целиком, с `--help` и `--doctor` |
| `shared/*` | **все каноны** + их README (`offtun`/`protect`/`lifecycle`/`hostproto`/`entry` — инжектируются всегда, из них `offtun` только в desktop-сборку; `socks5`/`dns` — по флагу дескриптора `socks5`/`dnsResolver`). Список — таблица `CANONS` в `build.py`, она же используется при инжекте, поэтому новый канон уезжает автору автоматически |
| `examples/<module>/` | сам модуль без билд-артефактов, со своим README (пути тоже поправлены) |
| `antinet-module.example.json` | образец манифеста авто-обновления — форма видна ДО первой сборки |

Автор: распаковать → `python build.py --doctor --os all` (что доустановить) →
`python build.py --module <X> --os all`. **Свой модуль — папкой РЯДОМ с образцом**
(`cp -r examples/module<X> examples/modulemymod`): `build.py` сканирует `examples/*/module.json` и
находит новый модуль сам, реестр править не надо, образец остаётся на месте для сверки.

Проверено прогоном вне репозитория: архив `echo` распакован в чистый каталог и собран под все
цели — каноны инжектировались, `--doctor` и `--help` отработали.

**Публикация — чтобы AntiNet ставил модуль по `antinet://`-ссылке и авто-обновлял** (полностью — `MODULE_API.md` §2.5):
```bash
python build.py --bundle --module qwdtt    # → dist-release/{<mod>-android-<abi>,<mod>-<os>_<arch>}.zip + antinet-module.json
```
По ZIP'у на каждый собранный таргет (Android `.so`+module.json на ABI, desktop-бинарь на os_arch —
единый плоский формат на обеих платформах). Залей их куда угодно со стабильным URL (ZIP'ы — GitHub
Releases-ассеты, S3, свой VPS+nginx: URL меняется на каждый релиз, это нормально), пропиши реальные URL'ы
в скелете `antinet-module.json` — но САМ манифест-файл держи на URL'е, который НЕ меняется от релиза к
релизу (напр. `raw.githubusercontent.com/.../main/antinet-module.json`, а не Release-ассет — тот
immutable per-release и разово запечёная в `updateUrl` ссылка на него навсегда останется на старой
версии). Пропиши этот стабильный URL в `updateUrl` (`module.json`), раздавай install-ссылку
`antinet://import?module=<base64url>`. AntiNet по ней скачает+тихо поставит модуль (файл в каталог
модулей, без системного установщика на любой платформе) и авто-обновит.

Готовую ссылку собирает сам AntiNet («Настройки → Модули → Поделиться модулем»), но формат открытый и
собрать её можно чем угодно: `module=` — это **base64url-no-pad** от компактного JSON
`{"s":"<scheme>","n":"<имя>","m":"<updateUrl-манифест>","h":"<homepage>"}`, где `s`+`n` обязательны, а
`m` и есть тот стабильный адрес манифеста из абзаца выше — без него получателю ставить неоткуда.
Полная спецификация (несколько `&module=`, совмещение с `url=<подписка>`, поведение при уже
установленной схеме) — **`MODULE_API.md` §2.5**.

---

## Кроссплатформенность

**Контракт платформо-агностичен**: ссылка → `[name, server]`/канон-link (сабкоманды) + helper =
SOCKS5 + protect-fd + стабильный порт + PDEATHSIG. Платформо-специфична только **обёртка**: discovery
(скан каталога — обе платформы одинаково), запуск helper'а (Android — `dlopen` в слот-процесс;
Desktop — форк), off-TUN (socket-level protect — для модуля это ЕДИНСТВЕННЫЙ механизм, package-level
TUN-исключение здесь не годится). Переписывается только обёртка — **сам helper-бинарь (включая
сабкоманды декода) переиспользуется как есть**. Чеклист порта — в `PORTING.md §5`.

## Лицензия

**MIT** (`LICENSE`). Она едет в КАЖДЫЙ авторский архив (`--package`), и это не формальность:
без файла лицензии опубликованные исходники по умолчанию под полным авторским правом, то есть
автор формально не вправе ни собрать образец, ни сделать на его основе свой модуль.

MIT выбран из-за инжекции канонов: `build.py` физически копирует `shared/*` в main-пакет
helper'а автора, значит наш код попадает в его бинарь. Копилефт (GPL/MPL) сделал бы производным
каждый сторонний модуль — MIT не навязывает автору ничего. Поэтому же `SPDX-License-Identifier: MIT`
стоит в шапке каждого канона и каждого исходника образца: инжектированный файл уезжает из архива
в чужое дерево, и маркер обязан ехать вместе с ним.

⚠ Своё происхождение у вложенных деревьев других модулей: `MasterDnsVPN` несёт собственный
MIT-`LICENSE` со своим копирайтом, апстрим qWDTT — **GPL-3.0**. Их условия наш `LICENSE` не
перекрывает, и заголовки в них не проставляются.
