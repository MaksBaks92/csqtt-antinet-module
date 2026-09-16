# Модуль «CSQTT» для AntiNet (`csqtt://`)

Протокол-модуль AntiNet для [CSQTT](https://github.com/amurcanov/csqtt): L3-туннель поверх TURN/RTP
(VK Calls). Helper поднимает SOCKS5 (сокет даёт хост), гоняет TCP/UDP через gVisor и обменивается
сырыми IPv4-пакетами с rust-движком по `127.0.0.1`.

Домашняя страница протокола: https://github.com/amurcanov/csqtt

## Что внутри

| Путь | Что это |
|---|---|
| `README.md` | этот файл — точка входа |
| `MODULE_SYSTEM.md` | обзор модульной системы AntiNet |
| `MODULE_API.md` | контракт helper'а |
| `PORTING.md` | внутренности AntiNet-стороны |
| `build.py` | сборщик. `python build.py --help`, `--doctor` |
| `tools/build-module.py` | Android-билдер (NDK clang → `.so`) |
| `examples/modulecsqtt/` | модуль: `module.json` + Go helper + rust-движок |
| `shared/` | каноны AntiNet (MIT). `build.py` копирует их в helper перед сборкой |
| `antinet-module.example.json` | образец манифеста авто-обновления |
| `LICENSE` | MIT — сборочная система и каноны |

## Лицензия

Лицензий **две**, и это не формальность.

- **Сборочная система и каноны** (`build.py`, `tools/`, `shared/`, доки) — **MIT** (`LICENSE`).
- **Сам модуль** `examples/modulecsqtt/` (Go-обвязка + rust-движок, производный от CSQTT) —
  **PolyForm Noncommercial 1.0.0** (`examples/modulecsqtt/LICENSE`). Коммерческое использование
  CSQTT требует отдельной лицензии у автора протокола.

Каноны MIT копируются в helper перед сборкой и ничего не навязывают копилефтом.

## Ссылка

```
csqtt://connect?v=2&host=<сервер>&peer=<порт>&password=<пароль>&hashes=<h1>+<h2>
csqtt://<password>@<host>:<port>          # legacy
```

VK-хеши можно не класть в ссылку:

- **Авто API** — модуль создаёт звонки через `calls.start` (как клиент CSQTT) и закрывает их при отключении.
- **Авто ВК** — rust создаёт один звонок через браузерную цепочку VK Calls.
- **Ручной** — поля «VK-хеш 1…6» в настройках модуля (или `hashes=` в ссылке). Авто-режимы эти поля не читают.

В авто-режимах нужен вход в VK через webview AntiNet. Фоновый пинг без токена/хешей пропускается (`pingNeedsConsent` + `canping`).

Сервер CSQTT менять не нужно: модуль говорит с ним тем же GETCONF/TUNCONF, что и приложение. `DEVICE_ID` хоста AntiNet уходит в GETCONF (привязка пароля к устройству, `DENIED:device_mismatch`).

## Сборка

Нужны **Go 1.26+** и **Rust 1.97+** (`cargo`).

Windows: rust-движок — `csqtt_engine.dll` рядом с `csqtt-helper.exe`. Сборка DLL требует
**C-компилятор**: Visual Studio 2022 Build Tools (C++) для `x86_64-pc-windows-msvc`, либо
MinGW-w64 и `rustup target add x86_64-pc-windows-gnu`. Одного `rustc` мало — `aws-lc-sys`
компилирует C.

Linux/macOS: helper с `CGO_ENABLED=1` + `libcsqtt_engine.so` / `.dylib` рядом.
Android: Go `c-shared` `.so` + rust `libcsqtt_engine.so` в том же ABI-каталоге (нужен NDK).

```
python build.py --doctor --os windows --module csqtt
python build.py --os windows --module csqtt --arch amd64 -y
python build.py --os android --module csqtt --abis arm64-v8a
```

Результат: `examples/modulecsqtt/dist/desktop/<os>_<arch>/` и `dist/android/<abi>/`.

## Публикация

1. Прописать в `examples/modulecsqtt/module.json` стабильный `updateUrl` и `version`.
2. `python build.py --module csqtt --os all` затем `python build.py --bundle --module csqtt`.
3. Залить ZIP'ы из `examples/modulecsqtt/dist-release/` и манифест по адресу `updateUrl`.

Install-ссылка: `antinet://import?module=<base64url JSON>` с ключами `s=csqtt`, `n=CSQTT`, `m=<updateUrl>`.
