# Discovery modules for entry event `HASHED_PASSWORD` (BBOT)
This doc is entry-event based and lists modules that support `HASHED_PASSWORD` input and the events they emit.

## Entry event model
- Entry event: `HASHED_PASSWORD`
- Selection rule: modules that consume `HASHED_PASSWORD` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `HASHED_PASSWORD` modules (example):
  - `bbot -t example.com -m leaklookup`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m leaklookup -rf passive`

## Enable a specific set of `HASHED_PASSWORD` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m leaklookup`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m leaklookup -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `EMAIL_ADDRESS`: `leaklookup`.
- Emit `HASHED_PASSWORD`: `leaklookup`.
- Emit `PASSWORD`: `leaklookup`, `leaklookup_hash`.
- Emit `USERNAME`: `leaklookup`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `hashed_password-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./hashed_password-discovery-yes.yml`

```yaml
description: HASHED_PASSWORD discovery with all modules marked "Should use = Yes"

modules:
  - leaklookup

config:
  modules:
    leaklookup:
      api_key: ${env:LEAKLOOKUP_API_KEY}
```

## Modules supporting entry event `HASHED_PASSWORD`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| leaklookup | EMAIL_ADDRESS | Module `leaklookup` functionality. | Yes | Yes, paid API approved | Yes |
| leaklookup | HASHED_PASSWORD | Module `leaklookup` functionality. | Yes | Yes, paid API approved | Yes |
| leaklookup | PASSWORD | Module `leaklookup` functionality. | Yes | Yes, paid API approved | Yes |
| leaklookup | USERNAME | Module `leaklookup` functionality. | Yes | Yes, paid API approved | Yes |
| leaklookup_hash | PASSWORD | Query leak-lookup.com for plaintext passwords using hashes | Yes | Yes | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
