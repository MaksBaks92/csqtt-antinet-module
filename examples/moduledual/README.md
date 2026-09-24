# Dual module skeleton (CSQTT + qWDTT)

Ветка: `dual/csqtt-qwdtt` (не трогает `main` / релизы 1.2.x).

Один AntiNet-модуль, две схемы:

| Схема | Сервер | Datapath (план) |
|-------|--------|-----------------|
| `csqtt://` | CSQTT (WIRE-3) | существующий rust-engine + gVisor |
| `qwdtt://` | qWDTT VPS ([SpaceNeuroX](https://github.com/SpaceNeuroX/proxy-turn-vk-android) `server/`) | клиентский путь из `go_client` / antinet-qwdtt |

**Серверную часть qWDTT в модуль не кладём** — она остаётся на VPS пользователя.

См. [ARCHITECTURE.md](ARCHITECTURE.md) и [VENDOR.md](VENDOR.md).

## Статус

`0.1.0-dual-skeleton` — только роутер по схеме + заглушки веток. Connect ещё не поднимает туннель.
