# Custom subconverter build

This fork adds a small build-time patch for personal Mihomo fallback usage while leaving the upstream source files unchanged in the repository.

## What this build changes

`patches/fallback-health-fields.patch` extends `custom_groups` TOML handling for `type = "fallback"` so these fields are parsed and emitted into the generated Clash/Mihomo YAML:

```toml
[[custom_groups]]
name = "🛟 故障切换"
type = "fallback"
rule = [".*"]
url = "http://www.gstatic.com/generate_204"
interval = 300
lazy = false
timeout = 5000
max-failed-times = 3
expected-status = 204
```

Supported added/normalized fields:

- `lazy`
- `timeout`
- `tolerance`
- `max-failed-times`
- `expected-status`
- `evaluate-before-use`

`expected-status` can be written either as a TOML integer (`204`) or as a TOML string (`"204"`).

## Build locally

```bash
docker build -f Dockerfile.custom -t subconverter:custom .
docker run --rm -p 25500:25500 subconverter:custom
curl http://127.0.0.1:25500/version
```

## Build with GitHub Actions

Run **Actions → Custom Docker Image → Run workflow**.

Choose one platform:

- `linux/amd64` for common Intel/AMD NAS
- `linux/arm64` for ARM NAS

The workflow publishes:

```text
ghcr.io/moekyo/subconverter:custom
ghcr.io/moekyo/subconverter:latest
```

## NAS compose example

Keep real subscription URLs and private config on the NAS. Do not bake them into the public image.

```yaml
services:
  subconverter:
    image: ghcr.io/moekyo/subconverter:custom
    container_name: subconverter
    ports:
      - "25500:25500"
    volumes:
      - /volume1/docker/subconverter/pref.toml:/base/pref.toml:ro
      - /volume1/docker/subconverter/groups.toml:/base/snippets/groups.toml:ro
      - /volume1/docker/subconverter/rulesets.toml:/base/snippets/rulesets.toml:ro
      - /volume1/docker/subconverter/custom-rules:/base/custom-rules:ro
    restart: always
```
