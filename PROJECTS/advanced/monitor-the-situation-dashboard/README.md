<!--
©AngelaMos | 2026
README.md
-->

# Monitor the Situation

Operator-grade real-time situational awareness dashboard. Single-binary Go backend, React 19 frontend, Postgres + Redis, fronted by nginx and (optionally) a Cloudflare Tunnel.

> The phrase "Monitoring the situation" is a Twitter/X meme from June 2025. This is the version that actually monitors the situation.

## Stack

| Layer       | Tech                                                       |
| ----------- | ---------------------------------------------------------- |
| Backend     | Go 1.22, chi router, `coder/websocket`, `goose` migrations |
| Frontend    | React 19, Vite, TanStack Query, Zustand, MapLibre, D3      |
| Storage     | Postgres 16 (BRIN-indexed time-series), Redis 7            |
| Ingress     | nginx (dev + prod), Cloudflare Tunnel (prod)               |
| Build / run | `just` recipes, multi-stage Docker, air for live reload    |

## Data sources

| Panel                          | Source                       | Cadence    | Auth                                          |
| ------------------------------ | ---------------------------- | ---------- | --------------------------------------------- |
| Mass-scan firehose             | DShield (SANS ISC)           | 1h         | none                                          |
| Internet outages + BGP hijacks | Cloudflare Radar             | 5m         | `CF_RADAR_TOKEN` (Radar:Read scope)           |
| CVE velocity + EPSS            | NVD CVE 2.0 + FIRST EPSS     | 2h         | `NVD_API_KEY` (optional, raises rate limit)   |
| CISA KEV                       | CISA KEV catalog             | 1h         | none                                          |
| Ransomware victims             | ransomware.live              | 15m        | none                                          |
| Live BTC + ETH ticks           | Coinbase Advanced Trade WS   | persistent | none                                          |
| Earthquakes (M2.5+)            | USGS GeoJSON feed            | 1m         | none                                          |
| Space weather                  | NOAA SWPC (5 endpoints)      | 1m / 3h    | none                                          |
| World events                   | Wikipedia ITN + GDELT v2 API | 5m / 15m   | none                                          |
| ISS position                   | wheretheiss.at + CelesTrak   | 10s / 24h  | none                                          |
| IP enrichment                  | GreyNoise Community          | on-demand  | `GREYNOISE_API_KEY` (optional, free tier)     |

## Quickstart (development)

```bash
cp .env.example .env
# fill .env: POSTGRES_PASSWORD, JWT_SECRET, NOTIFICATION_ENCRYPTION_KEY
just dev-start
just migrate-dev
open http://localhost:8432
```

JWT signing keys auto-generate at `backend/keys/private.pem` on first boot. The dev stack binds host ports `8432` (nginx) / `5432` (backend) / `4432` (postgres) / `6432` (redis) / `3432` (vite).

### Smoke checks

```bash
curl -s http://localhost:8432/api/v1/healthz
curl -s http://localhost:8432/api/v1/snapshot | jq .
docker run --rm -i --network host ghcr.io/vi/websocat:latest \
    "ws://localhost:8432/api/v1/ws?topics=heartbeat"
```

## Production (Cloudflare Tunnel)

```bash
cp .env.example .env
# fill production secrets including CLOUDFLARE_TUNNEL_TOKEN
just tunnel-start
just migrate
```

## Tests

```bash
cd backend && go test -race ./...
```

## Layout

```
backend/    Go services (cmd/api, internal/{events,bus,ws,snapshot,collectors,...})
frontend/   React 19 dashboard
conf/       nginx and per-environment Docker configs
migrations/ goose SQL migrations (mounted into the backend container)
```
