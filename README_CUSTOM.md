# Custom subconverter build

This fork directly adds fallback health-check field support in the source code for Mihomo usage — no build-time patching.

## What this build adds

### Fallback health-check fields

`custom_groups` TOML handling for `type = "fallback"` parses and emits these fields into the generated Clash/Mihomo YAML:

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

Supported fields:

- `lazy`
- `timeout`
- `tolerance`
- `max-failed-times`
- `expected-status`
- `evaluate-before-use`

`expected-status` can be a TOML integer (`204`) or a TOML string (`"204"`).

### Per-subscription fingerprint stripping

Fingerprint stripping is opt-in per subscription. Append this local-only fragment marker to a subscription URL:

```text
#subconverter_strip_fingerprint=1
```

Example:

```text
https://example.com/subscription/token#subconverter_strip_fingerprint=1
```

The marker is removed before the upstream HTTP request is sent. Only marked subscriptions use the compatibility behavior; unmarked subscriptions retain the original subconverter request behavior.

For a marked subscription, the outbound request:

- does not add `SubConverter-Request` or `SubConverter-Version`;
- does not add the legacy GET `Content-Type: application/json;charset=utf-8` fingerprint;
- does not forward inbound `Host` or hop-by-hop proxy headers to the upstream subscription origin;
- still preserves normal end-to-end headers such as `User-Agent`, `Accept`, `Accept-Language`, and `Accept-Encoding` when supplied by the caller.

The marker is intentionally part of the local/cache URL identity, so a normal subscription and the same subscription in fingerprint-stripping mode do not share a cache entry.

## Build locally

```bash
docker build -f Dockerfile.custom -t subconverter:custom .
docker run --rm -p 25500:25500 subconverter:custom
curl http://127.0.0.1:25500/version
```

## Build with GitHub Actions

Run **Actions → Custom Docker Image → Run workflow**.

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
