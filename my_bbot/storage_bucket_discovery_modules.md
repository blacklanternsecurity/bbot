# Discovery modules for entry event `STORAGE_BUCKET` (BBOT)
This doc is entry-event based and lists modules that support `STORAGE_BUCKET` input and the events they emit.

## Entry event model
- Entry event: `STORAGE_BUCKET`
- Selection rule: modules that consume `STORAGE_BUCKET` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `STORAGE_BUCKET` modules (example):
  - `bbot -t example.com -m baddns_direct bucket_amazon bucket_digitalocean bucket_file_enum bucket_firebase bucket_google`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m baddns_direct bucket_amazon bucket_digitalocean bucket_file_enum bucket_firebase bucket_google -rf passive`

## Enable a specific set of `STORAGE_BUCKET` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m baddns_direct bucket_amazon bucket_digitalocean bucket_file_enum bucket_firebase bucket_google`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m baddns_direct bucket_amazon bucket_digitalocean bucket_file_enum bucket_firebase bucket_google -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `FINDING`: `baddns_direct`, `bucket_amazon`, `bucket_digitalocean`, `bucket_firebase`, `bucket_google`, `bucket_microsoft`.
- Emit `STORAGE_BUCKET`: `bucket_amazon`, `bucket_digitalocean`, `bucket_firebase`, `bucket_google`, `bucket_microsoft`.
- Emit `URL_UNVERIFIED`: `bucket_file_enum`.
- Emit `VULNERABILITY`: `baddns_direct`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `storage_bucket-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./storage_bucket-discovery-yes.yml`

```yaml
description: STORAGE_BUCKET discovery with all modules marked "Should use = Yes"

modules:
  - baddns_direct
  - bucket_amazon
  - bucket_digitalocean
  - bucket_file_enum
  - bucket_firebase
  - bucket_google
  - bucket_microsoft
```

## Modules supporting entry event `STORAGE_BUCKET`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| baddns_direct | FINDING | Module `baddns_direct` functionality. | No | Yes, recommended | Yes |
| baddns_direct | VULNERABILITY | Module `baddns_direct` functionality. | No | Yes, recommended | Yes |
| bucket_amazon | FINDING | Module `bucket_amazon` functionality. | No | Yes, recommended | Yes |
| bucket_amazon | STORAGE_BUCKET | Module `bucket_amazon` functionality. | No | Yes, recommended | Yes |
| bucket_digitalocean | FINDING | Module `bucket_digitalocean` functionality. | No | Yes, recommended | Yes |
| bucket_digitalocean | STORAGE_BUCKET | Module `bucket_digitalocean` functionality. | No | Yes, recommended | Yes |
| bucket_file_enum | URL_UNVERIFIED | Enumerate files in public storage buckets | No | Yes, recommended | Yes |
| bucket_firebase | FINDING | Module `bucket_firebase` functionality. | No | Yes, recommended | Yes |
| bucket_firebase | STORAGE_BUCKET | Module `bucket_firebase` functionality. | No | Yes, recommended | Yes |
| bucket_google | FINDING | Adapted from https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/gcpbucketbrute.py | No | Yes, recommended | Yes |
| bucket_google | STORAGE_BUCKET | Adapted from https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/gcpbucketbrute.py | No | Yes, recommended | Yes |
| bucket_microsoft | FINDING | Module `bucket_microsoft` functionality. | No | Yes, recommended | Yes |
| bucket_microsoft | STORAGE_BUCKET | Module `bucket_microsoft` functionality. | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
