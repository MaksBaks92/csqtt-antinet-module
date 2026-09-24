# Dual module — CSQTT + qWDTT

Ветка: `dual/csqtt-qwdtt` (не `main`).

Один helper, две схемы:

| LINK | Datapath | Сервер |
|------|----------|--------|
| `csqtt://…` | gVisor + rust CSQTT engine (`csqtt_*.go` + `rustDir`) | CSQTT WIRE-3 |
| `qwdtt://…` / `wdtt://…` | vendored client (`internal/qwdtt`, GPL) | VPS SpaceNeuroX `server/` |

## Статус `0.2.0-dual`

- Роутер по `LINK` в `cmd/helper/main.go`
- CSQTT-ветка: полный helper (как modulecsqtt), общие AntiNet-каноны
- qWDTT-ветка: клиент из antinet qwdtt-module + shims на hostproto/protect
- `go build ./cmd/helper` (с inject canons) — OK при `CGO_ENABLED=0` (движок CSQTT на устройстве с cgo)
- Сервер qWDTT **не** в бандле — только клиент

См. [ARCHITECTURE.md](ARCHITECTURE.md), [VENDOR.md](VENDOR.md), [NOTICE](NOTICE).

## Сборка

```bash
python build.py --os android --module dual --abis arm64-v8a -y
```

Или desktop smoke: inject + `go build` из `examples/moduledual/native/dual`.
