# Subserver - Clash Subscription Server

Go implementation of Clash subscription conversion service with integrated subconverter.

## Features

- Clash/Surfboard subscription generation
- Cloudflare better IPs integration
- Vmess node processing with SNI fix
- Built-in subconverter (no separate service needed)
- Concurrent conversion with lock management
- Response caching for performance

## Quick Start

### Docker Compose

```bash
cp .env.example .env
# Edit .env with your credentials
docker-compose up -d
```

### Manual Docker

```bash
docker run -d \
  -p 8080:8080 \
  -e SUBSCRIPTION_URLS=https://zcvss.com/microsoft/db134ff893149b3af98c893c910d89f3 \
  ghcr.io/hzhq1255/my-clash-config-rule/subserver:0.0.2
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SERVER_PORT` | No | 8080 | HTTP server port |
| `LOG_LEVEL` | No | info | Log level (debug/info) |
| `SUBSCRIPTION_URLS` | Yes | - | One or more direct subscription URLs, separated by newlines |
| `EXTEND_SUB_NODES` | No | - | Additional nodes to prepend |
| `GHPROXY_DOMAIN` | No | ghp.ci | GitHub proxy domain |
| `SUBCONVERTER_VERSION` | No | v0.9.2 | Subconverter version |
| `SUBCONVERTER_DOWNLOAD_URL` | No | - | Custom subconverter URL |

Deprecated but still parsed:

| Variable | Description |
|----------|-------------|
| `ZCSSR_USER_EMAIL` | Legacy login email, no longer used by the active subscription flow |
| `ZCSSR_USER_PASSWD` | Legacy login password, no longer used by the active subscription flow |
| `ZCSSR_DOMAIN` | Legacy site domain, kept for possible future authenticated requests |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sub/links.txt` | GET | Merged subscription (base64) |
| `/sub/normal.yaml` | GET | Clash configuration |
| `/sub/surfboard.txt` | GET | Surfboard configuration |
| `/sub/convert_cf_better_ips` | GET | CF better IPs conversion |
| `/health` | GET | Health check |

## Development

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o server ./cmd/server

# Run
./server
```

## Deployment

### Racknerd

Update `/root/services/docker-compose.yml`:

```yaml
services:
  sub-server:
    image: ghcr.io/hzhq1255/my-clash-config-rule/subserver:0.0.1
    # ... environment variables
```

Then:

```bash
docker-compose pull
docker-compose up -d sub-server
```

## License

MIT
