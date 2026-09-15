# modulecsqtt — CSQTT для AntiNet

Companion-модуль AntiNet для протокола [CSQTT](https://github.com/amurcanov/csqtt)
(PolyForm Noncommercial 1.0.0). Helper — Go (SOCKS5 + gVisor), движок туннеля — rust-client CSQTT
как `cdylib`, загружаемый в том же процессе.

## Ссылка

```
csqtt://connect?v=2&host=<host>&peer=<port>&password=<password>&hashes=<hash>+<hash>
```

`hashes` можно не класть в ссылку, а задать настройкой модуля `vkHashes`.

## Раскладка

| Путь | Что |
|---|---|
| `module.json` | дескриптор (schemes, settings, helperBinary, build) |
| `native/csqtt/cmd/helper/` | Go helper: разбор ссылки, SOCKS5, protect, пакетный мост |
| `native/csqtt/tunnel/` | gVisor netstack (сырые IPv4) |
| `native/csqtt-engine/` | rust-движок (форк rust-client CSQTT + C FFI + protect-hook) |

На Android рядом с `libcsqtthelper.so` должен лежать `libcsqtt_engine.so`.
На Windows рядом с `csqtt-helper.exe` — `csqtt_engine.dll`.
