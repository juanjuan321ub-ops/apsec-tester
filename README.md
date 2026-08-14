# 🛡️ APSec Tester

**Security-first API security scanner for OpenAPI 3.x — static contract analysis _and_ live probing.**

APSec Tester audits an API two ways: it statically analyzes an OpenAPI 3.x
contract, and it actively probes a running target over HTTP. Findings are mapped
to the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/),
scored by severity, and exported as console, JSON, Markdown or a self-contained
HTML report. It returns CI-friendly exit codes.

![status](https://img.shields.io/badge/status-alpha-orange)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![tests](https://img.shields.io/badge/tests-56%20passing-brightgreen)

---

## ✨ Features

- **Full pipeline** — `recon` (assets) → `crawl` (browser routes) → `scan`/`probe`/`flow`/`fuzz`/`chaos` (find) → `triage` (prioritize) → `report` (bounty-ready).
- **Authorization & logic abuse** — BOLA/IDOR, BFLA, mass assignment, broken auth (`flow`).
- **Injection & resilience** — error-based SQLi and reflected XSS (`fuzz`); stack-trace/info-leak under fault (`chaos`).
- **Offline AI triage** — ranks findings by bounty value; no data leaves your machine.
- **Scope-gated by design** — a mandatory allow-list; the tool physically refuses out-of-scope hosts (safe for authorized bug-bounty work).
- **Multiple inputs** — OpenAPI 3.x (JSON/YAML) and Postman Collections (v2.1).
- **OWASP-mapped checks** — every finding links to the relevant OWASP API category.
- **Four report formats** — colorized console, JSON, Markdown (for tickets), and offline HTML.
- **Scan modes** — `quick` (cheap, single-request checks) and `full` (adds burst probes).
- **Custom rules** — extend probing with a YAML rules file, no Python needed.
- **Security by design** — `safe_load` only, no remote `$ref` fetching (no SSRF), no ambient proxy.
- **CI-native** — configurable `--fail-on` gate and documented exit codes.

## 📦 Installation

```bash
git clone https://github.com/your-org/apsec-tester.git
cd apsec-tester
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

This exposes the `apsec` command. You can also run it via `python -m apsec`.

## 🚀 Usage

### Static scan (OpenAPI contract)

```bash
apsec scan examples/petstore-insecure.yaml
apsec scan openapi.yaml --fail-on critical --json out.json --md out.md --html out.html
apsec scan openapi.yaml --no-deep       # skip openapi-spec-validator deep validation
```

### Flow — BOLA / IDOR & broken-auth testing (the differentiator)

Declare identities and a flow; the engine runs the happy path, captures resource
ids, then replays object-access steps as **other identities** and **with no
credentials**. Success = a real authorization bug (OWASP API1/API2).

```yaml
# flow.yaml
base_url: https://api.example.com
identities:
  alice: { headers: { Authorization: "Bearer TOKEN_A" } }
  bob:   { headers: { Authorization: "Bearer TOKEN_B" } }
flow:
  name: Access a document by id
  steps:
    - id: create
      identity: alice
      method: POST
      path: /documents
      json: { title: "secret" }
      capture: { doc_id: "$.id" }
    - id: read
      identity: alice
      method: GET
      path: /documents/{doc_id}
      abuse: [bola, unauth]     # replay as bob, and with no auth
```

```bash
apsec flow flow.yaml --scope scope.yaml        # scope-gated
```

If `bob` (or an anonymous request) can read alice's document, APSec reports a
**CRITICAL** Broken Object Level Authorization finding with the exact request.

### Recon (asset discovery — scope-gated)

Discovery runs **only inside an authorized scope**. Define it once:

```yaml
# scope.yaml
include:
  - "*.example.com"
exclude:
  - "blog.example.com"
```

```bash
apsec recon scope.yaml                          # passive CT-log discovery + DNS + alive probe
apsec recon scope.yaml -w subdomains.txt        # add a subdomain wordlist
apsec recon scope.yaml --json assets.json       # machine-readable output
```

The `probe` command can enforce the same scope, refusing any out-of-scope target:

```bash
apsec probe https://api.example.com --scope scope.yaml
```

### Live probe (running API)

```bash
apsec probe https://api.example.com --mode full
apsec probe https://api.example.com --mode quick --html report.html
apsec probe --postman examples/collection.postman.json          # derive URL from collection
apsec probe https://api.example.com --rules examples/custom-rules.yaml
```

### Common options

| Option              | Applies to   | Description                                             |
|---------------------|--------------|---------------------------------------------------------|
| `--fail-on, -f`     | scan, probe  | Min severity that exits non-zero (default `high`).      |
| `--json, -j`        | scan, probe  | Write a JSON report.                                    |
| `--md, -m`          | scan, probe  | Write a Markdown report (great for Jira/GitHub tickets).|
| `--html`            | scan, probe  | Write a self-contained HTML report.                     |
| `--quiet, -q`       | scan, probe  | Suppress the console report.                            |
| `--verbose, -v`     | scan, probe  | Debug logging to stderr.                                |
| `--mode`            | probe        | `quick` or `full`.                                      |
| `--postman, -p`     | probe        | Postman collection to derive the base URL from.         |
| `--rules, -r`       | probe        | YAML file of custom rules.                              |
| `--no-deep`         | scan         | Skip openapi-spec-validator deep validation.            |

### Exit codes

| Code | Meaning                                             |
|------|-----------------------------------------------------|
| `0`  | Ran; no finding reached the `--fail-on` gate.       |
| `1`  | Ran; a finding met/exceeded the gate.               |
| `2`  | Usage error (bad arguments).                        |
| `3`  | Spec/collection could not be loaded or validated.   |
| `4`  | Runtime error (e.g. target unreachable).            |

## 🔎 Checks

### Static (`scan`)

| ID              | Severity | OWASP  | Catches                                                       |
|-----------------|----------|--------|--------------------------------------------------------------|
| `APSEC-AUTH-001`| HIGH/MED | API2   | No security schemes / no global `security` applied.          |
| `APSEC-AUTH-002`| HIGH     | API2/5 | State-changing ops (POST/PUT/PATCH/DELETE) with no effective auth. |
| `APSEC-AUTH-003`| MEDIUM   | API2   | HTTP Basic auth, or API key passed in the query string.      |
| `APSEC-TLS-001` | HIGH     | API8   | Server URLs declared over plaintext `http://`.               |

### Live (`probe`)

| ID              | Severity      | OWASP | Catches                                               |
|-----------------|---------------|-------|-------------------------------------------------------|
| `APSEC-HDR-001` | INFO→HIGH     | API8  | Missing security headers (HSTS, CSP, nosniff, etc.).  |
| `APSEC-CORS-001`| LOW→CRITICAL  | API8  | Overly permissive / origin-reflecting CORS.           |
| `APSEC-RATE-001`| MEDIUM        | API4  | No rate limiting detected under a request burst.      |
| `APSEC-INFO-001`| LOW           | API8  | Technology/version banners in response headers.       |

### Authorization abuse (`flow`)

| ID              | Severity  | OWASP | Catches                                              |
|-----------------|-----------|-------|------------------------------------------------------|
| `APSEC-BOLA-001`| CRITICAL  | API1  | Another identity can access an owner's object (IDOR).|
| `APSEC-AUTH-010`| HIGH      | API2  | A protected resource is served with no credentials.  |
| `APSEC-BFLA-001`| HIGH      | API5  | Lower-privilege identity can call a privileged function. |
| `APSEC-MASS-001`| HIGH      | API3  | Client can set server-controlled properties (mass assignment). |

### Injection (`fuzz`) & Resilience (`chaos`)

| ID              | Severity  | Catches                                              |
|-----------------|-----------|------------------------------------------------------|
| `APSEC-SQLI-001`| CRITICAL  | Error-based SQL injection in a query parameter.      |
| `APSEC-XSS-001` | HIGH      | Reflected XSS (verbatim script reflection in HTML).  |
| `APSEC-CHAOS-001`| MEDIUM   | Stack trace / debug page leaked under a fault.       |
| `APSEC-CHAOS-002`| LOW      | Internal filesystem path disclosed under a fault.    |

Try it against the bundled fixtures:

```bash
apsec scan examples/petstore-insecure.yaml   # exits 1 — several findings
apsec scan examples/petstore-secure.yaml     # exits 0 — clean
```

## 🧩 Custom rules

Drop a YAML file and pass it with `--rules`. Each rule performs a safe request
and asserts on the response (inspired by Nuclei templates):

```yaml
rules:
  - id: CUSTOM-HEALTH-001
    name: Health endpoint should not expose build version
    severity: medium
    request:
      method: GET
      path: /health
    expect:
      status: 200
      header_absent: [x-build-version]
```

## 🧰 All commands

```bash
apsec recon  scope.yaml                       # discover in-scope assets
apsec crawl  https://app.example.com -s scope.yaml   # browser route discovery (needs [browser])
apsec scan   openapi.yaml                      # static OpenAPI contract analysis
apsec probe  https://api.example.com -s scope.yaml   # live headers/CORS/rate-limit
apsec flow   flow.yaml -s scope.yaml           # BOLA/IDOR/BFLA/mass-assignment/broken-auth
apsec fuzz   "https://api.example.com/x?id=1" -s scope.yaml   # SQLi + reflected XSS
apsec chaos  https://api.example.com/x -s scope.yaml # fault-induced info leakage
apsec triage report.json                       # prioritize findings (offline)
apsec report report.json -m submission.md      # bounty-ready Markdown
```

Optional browser extra: `pip install "apsec-tester[browser]" && playwright install chromium`.

## 🏗️ Architecture

```
src/apsec/
├── cli.py                    # Typer CLI — the ONLY layer that exits the process
├── core/                     # console (ANSI), logger, config (exit codes), errors
├── parsers/
│   ├── openapi.py            # safe JSON/YAML loader + shallow + deep validation
│   └── postman.py            # Postman v2.1 collection loader
├── scanner/
│   ├── models.py             # Severity, Finding, ScanResult
│   ├── engine.py             # static engine (isolates faulty checks)
│   ├── checks/               # static checks: authentication.py, transport.py
│   └── live/
│       ├── engine.py         # live engine (quick/full, connectivity pre-check)
│       ├── rules.py          # custom YAML rules loader + runner
│       └── checks/           # headers.py, cors.py, ratelimit.py, info.py
└── reporters/                # console, json, markdown, html
```

**Design principles** (priority order): Security → Portability → Maintainability → Innovation.

- Checks are **pure/isolated**: a faulty check is logged and skipped, never aborting a run.
- Adding a rule is a one-line registration in the relevant `checks/__init__.py`.
- All file and network I/O is wrapped and surfaced as typed errors.

## 🧪 Development

```bash
pytest            # run the 26-test suite
ruff check .      # lint
mypy              # type-check (strict)
```

## 🗺️ Roadmap

- [ ] Injection heuristics (SQLi / XSS / command injection) and BOLA/IDOR probes.
- [ ] Authenticated probing (inject bearer tokens / API keys per endpoint).
- [ ] SARIF output for GitHub code scanning.
- [ ] Baseline / diff mode to gate only *new* findings in CI.

## 📄 License

MIT © Juan
