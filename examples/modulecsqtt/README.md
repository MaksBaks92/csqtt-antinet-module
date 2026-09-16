# modulecsqtt — CSQTT для AntiNet

Companion-модуль AntiNet для протокола [CSQTT](https://github.com/amurcanov/csqtt)
(PolyForm Noncommercial 1.0.0). Helper — Go (SOCKS5 + gVisor), движок туннеля — rust-client CSQTT
как `cdylib`, загружаемый в том же процессе.

## Ссылка

```
csqtt://connect?v=2&host=<host>&peer=<port>&password=<password>&hashes=<hash>+<hash>
```

VK-хеши можно не класть в ссылку. Три режима, как в клиенте CSQTT:

- **Авто API** (по умолчанию) — helper вызывает `calls.start`, создаёт 1–6 звонков
  по числу воркеров и при остановке закрывает их через `calls.forceFinish`.
- **Авто ВК** — rust-движок создаёт один звонок (`vchat.startConversation`).
- **Ручной** — поля «VK-хеш 1…6» в настройках модуля (или `hashes=` в ссылке).

В авто-режимах helper открывает вход в VK через webview хоста AntiNet. Cookie сессии
остаются в хранилище AntiNet.

## Раскладка

| Путь | Что |
|---|---|
| `module.json` | дескриптор (schemes, settings, helperBinary, build) |
| `native/csqtt/cmd/helper/` | Go helper: разбор ссылки, SOCKS5, protect, пакетный мост |
| `native/csqtt/tunnel/` | gVisor netstack (сырые IPv4) |
| `native/csqtt-engine/` | rust-движок (форк rust-client CSQTT + C FFI + protect-hook) |

На Android рядом с `libcsqtthelper.so` должен лежать `libcsqtt_engine.so`
(хост распаковывает весь плоский ZIP ABI-каталога). Helper ищет движок рядом с собой
и по `/proc/self/maps` — `os.Executable()` в слот-процессе указывает на бинарь AntiNet, не на модуль.
На Windows рядом с `csqtt-helper.exe` — `csqtt_engine.dll`.
