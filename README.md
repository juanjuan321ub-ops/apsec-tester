<div align="center">

<img alt="APSec Tester" src="https://capsule-render.vercel.app/api?type=waving&color=0:0f2027,50:203a43,100:2c5364&height=210&section=header&text=APSec%20Tester&fontColor=ffffff&fontSize=54&fontAlignY=38&animation=fadeIn" width="100%" />

# 🛡️ APSec Tester

**Security-first API security scanner for OpenAPI 3.x — static contract analysis _and_ live probing.**

<a href="https://owasp.org/API-Security/editions/2023/en/0x11-t10/">
  <img alt="Security-first API security scanner for OpenAPI 3.x — static contract analysis and live probing" src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&pause=1200&color=36BCF7&center=true&vCenter=true&width=780&lines=Security-first+API+security+scanner+for+OpenAPI+3.x;static+contract+analysis+and+live+probing" />
</a>

<p align="center">
  <img alt="status: alpha" src="https://img.shields.io/badge/status-alpha-orange?style=for-the-badge" />
  <img alt="python: 3.11+" src="https://img.shields.io/badge/python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="license: MIT" src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
  <img alt="tests: 72 passing" src="https://img.shields.io/badge/tests-72_passing-brightgreen?style=for-the-badge" />
</p>

<p align="center">
  <img alt="Tech stack: Python, Git, GitHub" src="https://skillicons.dev/icons?i=py,git,github" />
</p>

<p align="center">
  <a href="https://owasp.org/API-Security/editions/2023/en/0x11-t10/">
    <img alt="OWASP API Security Top 10 (2023)" src="https://img.shields.io/badge/OWASP-API%20Security%20Top%2010%20(2023)-000000?style=for-the-badge&logo=owasp&logoColor=white" />
  </a>
</p>

</div>

APSec Tester audits an API two ways: it statically analyzes an OpenAPI 3.x
contract, and it actively probes a running target over HTTP. Findings are mapped
to the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/),
scored by severity, and exported as console, JSON, Markdown or a self-contained
HTML report. It returns CI-friendly exit codes.

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

---

## 📦 Installation

```bash
git clone https://github.com/your-org/apsec-tester.git
cd apsec-tester
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

This exposes the `apsec` command. You can also run it via `python -m apsec`.

---

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

Valid `abuse` keywords per step: `bola` (replay as another identity), `bfla`
(privilege escalation), `unauth` (replay with no credentials), and
`mass_assignment` (send a `mass_assign` payload and check if protected
properties stick).

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

| Option              | Applies to                     | Description                                             |
|---------------------|--------------------------------|---------------------------------------------------------|
| `--fail-on, -f`     | scan, probe, flow, fuzz, chaos | Min severity that exits non-zero (default `high`; `medium` for chaos). |
| `--json, -j`        | scan, probe, flow, fuzz, chaos, recon, crawl | Write a JSON report / asset list.         |
| `--md, -m`          | scan, probe, flow, fuzz, chaos, report | Write a Markdown report (great for Jira/GitHub tickets). |
| `--html`            | scan, probe, flow, fuzz, chaos | Write a self-contained HTML report.                     |
| `--quiet, -q`       | scan, probe, flow, fuzz, chaos, recon | Suppress the console report.                     |
| `--verbose, -v`     | all commands                   | Debug logging to stderr.                                |
| `--scope, -s`       | probe, flow, fuzz, chaos, crawl | Scope YAML; out-of-scope targets are refused/skipped.  |
| `--mode`            | probe                          | `quick` or `full`.                                      |
| `--postman, -p`     | probe                          | Postman collection to derive the base URL from.         |
| `--rules, -r`       | probe                          | YAML file of custom rules.                              |
| `--no-deep`         | scan                           | Skip openapi-spec-validator deep validation.            |
| `--base-url, -u`    | flow                           | Override the `base_url` declared in the flow file.      |
| `--url-file, -U`    | fuzz                           | File with one parameterized URL per line.               |
| `--wordlist, -w`    | recon                          | Optional subdomain wordlist (one per line).             |
| `--concurrency, -c` | recon                          | Max parallel hosts (default `20`).                      |
| `--max-pages`       | crawl                          | Maximum pages to visit (default `25`).                  |
| `--top, -n`         | triage                         | How many ranked findings to show (default `10`).        |

### Exit codes

| Code | Meaning                                             |
|------|-----------------------------------------------------|
| `0`  | Ran; no finding reached the `--fail-on` gate.       |
| `1`  | Ran; a finding met/exceeded the gate.               |
| `2`  | Usage error (bad arguments).                        |
| `3`  | Spec/collection could not be loaded or validated.   |
| `4`  | Runtime error (e.g. target unreachable).            |

---

## 🔎 Checks

### Static (`scan`)

| ID              | Severity | OWASP  | Catches                                                       |
|-----------------|----------|--------|--------------------------------------------------------------|
| `APSEC-AUTH-001`| HIGH/MED | API2   | No security schemes / no global `security` applied.          |
| `APSEC-AUTH-002`| HIGH     | API2/5 | State-changing ops (POST/PUT/PATCH/DELETE) with no effective auth. |
| `APSEC-AUTH-003`| MEDIUM   | API2   | HTTP Basic auth, or API key passed in the query string.      |
| `APSEC-TLS-001` | HIGH     | API8   | Server URLs declared over plaintext `http://`.               |
| `APSEC-DATA-001`| HIGH     | API3   | Sensitive field (password, token, ssn, etc.) in a response schema. |
| `APSEC-SSRF-001`| MEDIUM   | API7   | Parameter whose name/shape is a likely SSRF sink (url, callback…). |
| `APSEC-INV-002` | LOW      | API9   | Deprecated endpoint still exposed.                           |
| `APSEC-INV-003` | LOW      | API9   | Multiple API versions coexisting.                            |
| `APSEC-INV-004` | INFO     | API9   | Undocumented operations (missing operationId/summary).       |

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

---

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

---

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

---

## 🏗️ Architecture

```
src/apsec/
├── cli.py                    # Typer CLI — the ONLY layer that exits the process
├── core/                     # console (ANSI), logger, config (exit codes), errors, scope
├── parsers/
│   ├── openapi.py            # safe JSON/YAML loader + shallow + deep validation
│   └── postman.py            # Postman v2.1 collection loader
├── recon/                    # scope-gated asset discovery (CT logs, DNS, alive probe)
├── crawl/                    # headless-browser route discovery (needs [browser])
├── scanner/
│   ├── models.py             # Severity, Finding, ScanResult
│   ├── engine.py             # static engine (isolates faulty checks)
│   ├── injection.py          # SQLi + reflected-XSS fuzzer
│   ├── checks/               # static checks: authentication, transport,
│   │                         #   data_exposure, inventory, ssrf_surface
│   └── live/
│       ├── engine.py         # live engine (quick/full, connectivity pre-check)
│       ├── rules.py          # custom YAML rules loader + runner
│       └── checks/           # headers.py, cors.py, ratelimit.py, info.py
├── flow/                     # BOLA/IDOR/BFLA/mass-assignment/broken-auth abuse engine
├── chaos/                    # fault injection + info-leak signatures
├── ai/                       # offline triage (prioritize) + narrative
└── reporters/                # console, json, markdown, html, bounty
```

**Design principles** (priority order): Security → Portability → Maintainability → Innovation.

- Checks are **pure/isolated**: a faulty check is logged and skipped, never aborting a run.
- Adding a rule is a one-line registration in the relevant `checks/__init__.py`.
- All file and network I/O is wrapped and surfaced as typed errors.

---

## 🧪 Development

```bash
pytest            # run the 72-test suite
ruff check .      # lint
mypy              # type-check (strict)
```

---

## 🗺️ Roadmap

- [x] Injection heuristics (error-based SQLi / reflected XSS) via `fuzz`.
- [x] BOLA/IDOR/BFLA/mass-assignment probes via `flow`.
- [x] Offline AI triage of findings by bounty value.
- [ ] Command-injection and time-based (blind) injection heuristics.
- [ ] Authenticated probing (inject bearer tokens / API keys per endpoint).
- [ ] SARIF output for GitHub code scanning.
- [ ] Baseline / diff mode to gate only *new* findings in CI.
- [ ] GraphQL-aware checks.

---

## 📄 License

MIT © Juan

<div align="center">

<img alt="APSec Tester" src="https://capsule-render.vercel.app/api?type=waving&color=0:2c5364,50:203a43,100:0f2027&height=120&section=footer&text=APSec%20Tester&fontColor=ffffff&fontSize=26&fontAlignY=70&animation=fadeIn" width="100%" />

</div>
