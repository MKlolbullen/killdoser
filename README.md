# KillDoSer — Firewall & Service Stress-Testing Harness

KillDoSer generates controlled network load to exercise firewalls, WAFs,
load balancers, and backend services **in sandboxed lab environments**. It is
a tool for authorized security testing and capacity validation — not for use
against systems you do not own or have explicit written permission to test.

> **DISCLAIMER**: Unauthorized use against third-party infrastructure is
> illegal in most jurisdictions. Every run requires an explicit authorization
> assertion, and by default public-IP targets are refused.

---

## Why use it

Firewall rule sets are easy to write and hard to verify. KillDoSer lets you
pointedly exercise the behaviors a typical rule stack needs to enforce:

| Rule behavior being tested | Recommended mode            |
|----------------------------|-----------------------------|
| SYN rate / conntrack caps  | `tcp-connect`               |
| UDP rate limiting / DPI    | `udp-flood`                 |
| L7 policy / WAF rules      | `http-flood` (`--http2`)    |
| Idle-timeout / slow-drip   | `slowloris`                 |
| Port sweep / CIDR coverage | any mode + CIDR target      |

Each run produces a metrics summary with attempts, successes, errors
classified (`refused`, `timeout`, `reset`, `no-route`, `fd-exhausted`, …),
throughput (RPS), bytes sent, and latency percentiles (p50 / p95 / p99 / max).

---

## What's new vs. the original

The original `main.go` was a sequential prompt-driven script. This version is
a small, tested Go harness:

- **Concurrent worker pool** with a token-bucket rate limiter (PPS cap).
- **Four attack modes** (`tcp-connect`, `udp-flood`, `http-flood`, `slowloris`).
  HTTP mode issues real HTTP/1.1 or HTTP/2 requests, not raw bytes.
- **Proper CIDR iteration** (previously the CIDR was parsed but never used).
- **Target resolution** for domains, with IPv6 support and host:port forms.
- **Safety gates**: explicit `--i-have-authorization` flag, private-IP
  allowlist (RFC1918 / loopback / link-local / ULA / TEST-NETs) on by
  default, policy-enforced max workers and max PPS.
- **Metrics** with atomic counters and a bounded reservoir for latency
  percentiles; text or JSON summary output.
- **Graceful shutdown** on SIGINT/SIGTERM; `--duration` and `--count`
  guarantee termination.
- **Interactive mode kept** (`--interactive` or no flags) for backward compat.
- **Unit tests** covering target parsing, metrics, safety, config, and a
  local-loopback integration test for the attackers.

---

## Install

Requires Go 1.23+.

```bash
git clone https://github.com/MKlolbullen/killdoser.git
cd killdoser
go build -o killdoser
```

---

## Usage

```bash
./killdoser --help
```

### Examples

HTTP flood against a lab service for 15 seconds, HTTP/2, 128 workers:

```bash
./killdoser \
  --mode http-flood \
  --target lab.internal:8443 \
  --http-scheme https --http2 --insecure \
  --workers 128 --rate 5000 --duration 15s \
  --i-have-authorization \
  --json
```

TCP connect sweep across a /28 to exercise conntrack:

```bash
./killdoser \
  --mode tcp-connect \
  --target 192.168.1.0/28 --port 22 \
  --workers 64 --rate 2000 --duration 10s \
  --i-have-authorization
```

UDP packet burst:

```bash
./killdoser \
  --mode udp-flood \
  --target 10.0.0.5:5000 \
  --payload 'ping' --encoding base64 \
  --rate 10000 --duration 5s \
  --i-have-authorization
```

Slowloris against an HTTP endpoint (drip 20 headers, 5s apart, over many sockets):

```bash
./killdoser \
  --mode slowloris \
  --target 10.0.0.10:80 \
  --workers 256 --slow-headers 20 --slow-interval 5s --duration 2m \
  --i-have-authorization
```

Interactive prompts (the original workflow):

```bash
./killdoser --interactive
```

---

## Safety model

KillDoSer applies the following defaults. None can be disabled via config
file — they must be explicitly overridden on the command line.

1. **No run without authorization.** `--i-have-authorization` (or the
   interactive prompt) is required.
2. **Private-IP only.** Targets outside RFC1918 / loopback / link-local /
   ULA / TEST-NET ranges are refused unless `--allow-public` is also passed.
3. **Rate cap.** The default policy clamps requested PPS at 200k and
   `--workers` at 1024. Requesting more is silently clamped.
4. **Bounded CIDRs.** Expansions larger than 4096 endpoints are refused.
5. **Guaranteed termination.** You must set `--duration` and/or `--count`.

These defaults are defined in `internal/safety` and are unit-tested.

---

## Flags

| Flag                     | Description                                              |
|--------------------------|----------------------------------------------------------|
| `--mode`                 | `tcp-connect` \| `udp-flood` \| `http-flood` \| `slowloris` |
| `--target`               | host, host:port, IP, or CIDR                             |
| `--port`                 | default port when target has none                        |
| `--payload`              | raw bytes (TCP/UDP) or HTTP body                         |
| `--encoding`             | `none` \| `url` \| `html` \| `base64` \| `unicode`       |
| `--workers`              | concurrent workers (default 64)                          |
| `--rate`                 | send rate cap in PPS (default 1000, 0 = policy max)      |
| `--duration`             | wall-clock budget (default 30s)                          |
| `--count`                | total-send budget                                        |
| `--timeout`              | per-operation timeout (default 3s)                       |
| `--http-method`          | HTTP verb (default GET)                                  |
| `--http-path`            | request path                                             |
| `--http-scheme`          | `http` or `https`                                        |
| `--http-host`            | override Host header                                     |
| `--http2`                | prefer HTTP/2                                            |
| `--insecure`             | skip TLS verification (lab only)                         |
| `--slow-headers`         | slowloris drip header count                              |
| `--slow-interval`        | slowloris header drip interval                           |
| `--i-have-authorization` | required assertion                                       |
| `--allow-public`         | permit public-IP targets                                 |
| `--json`                 | JSON summary output                                      |
| `--quiet`                | suppress periodic progress                               |
| `--interactive`          | prompt for everything                                    |

---

## Project layout

```
killdoser/
├── main.go                    # orchestrator
├── internal/
│   ├── config/                # flag parsing + interactive wizard + validation
│   ├── safety/                # authorization & target policy
│   ├── target/                # IP/domain/CIDR -> []Endpoint
│   ├── ratelimit/             # token-bucket limiter
│   ├── metrics/               # atomic counters, latency reservoir
│   └── attack/                # Attacker interface + implementations + runner
└── README.md
```

---

## Development

```bash
go test ./...     # unit + integration tests
go vet ./...
go build ./...
```

---

## Legal

This project is licensed under the MIT License. By using this tool you agree
to use it only against systems you own or are explicitly authorized to test.
