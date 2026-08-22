# Contexto del Proyecto - APSec Tester

## Rol
Eres un experto en seguridad de APIs, pentesting y Python. Vamos a construir una herramienta profesional para Security QA enfocada en APIs.

## Nombre del Proyecto
**APSec Tester** - API Security Tester para QA.

## Objetivo
Permitir a un QA de Seguridad analizar rápidamente APIs (REST, GraphQL) que le entreguen (URL + OpenAPI, Postman collection, etc.) y generar reportes profesionales.

## Herramientas en las que inspirarse
- OWASP ZAP (funcionalidades de escaneo automatizado)
- Burp Suite (lógica de pruebas comunes)
- Nuclei (templates de pruebas)
- Spectral / Vacuum (validación de OpenAPI)

## Funcionalidades Obligatorias

1. **Soporte de entrada**
   - URL base + OpenAPI/Swagger file
   - Postman Collection
   - Archivo de endpoints manual

2. **Pruebas Automáticas**
   - Security Headers
   - Authentication / Authorization issues
   - Rate Limiting / Throttling
   - Common injections (SQLi, XSS, Command Injection)
   - Broken Object Level Authorization (BOLA)
   - CORS misconfiguration
   - Sensitive data exposure

3. **Reportes**
   - HTML profesional con evidencias
   - JSON
   - Markdown (para tickets)
   - Resumen OWASP API Security Top 10

4. **Modos**
   - Quick Scan (rápido)
   - Full Scan
   - Custom rules via YAML

## Requisitos Técnicos
- Python 3.11+
- CLI con Typer
- Usar `httpx` + `openapi-spec-validator` + reglas propias
- Código limpio, seguro y bien documentado
- Fácil de extender con nuevos tests

## Reglas
- Todo local cuando sea posible.
- Reportes claros, accionables y con nivel de severidad.
- Incluir ejemplos de uso en README.
- Preparar integración con CI/CD.

## Estado actual (2026-08-22)

Ya construido y con 72 tests pasando. Comandos CLI: `recon`, `crawl`, `scan`,
`probe`, `flow`, `fuzz`, `chaos`, `triage`, `report`, `version`.

- **Entrada:** OpenAPI 3.x (JSON/YAML) y Postman v2.1. (Falta: archivo de
  endpoints manual como formato dedicado.)
- **Checks estáticos (`scan`):** auth (AUTH-001/002/003), TLS-001,
  data_exposure (DATA-001), inventory (INV-002/003/004), ssrf_surface (SSRF-001).
- **Checks live (`probe`):** headers (HDR-001), CORS-001, rate-limit (RATE-001),
  info-leak (INFO-001) + reglas YAML propias (`--rules`).
- **Autorización/lógica (`flow`):** BOLA-001, BFLA-001, AUTH-010 (unauth),
  MASS-001.
- **Inyección (`fuzz`):** SQLi error-based (SQLI-001), XSS reflejado (XSS-001).
  **Pendiente:** command injection y blind/time-based (aún no implementados
  pese a estar en "Funcionalidades Obligatorias").
- **Resiliencia (`chaos`):** stack-trace/info-leak bajo fault (CHAOS-001/002).
- **Reportes:** console, JSON, Markdown, HTML self-contained, y bounty-ready.
- **Seguridad por diseño:** todo scope-gated (`--scope`), `safe_load`, sin fetch
  de `$ref` remotos, sin proxy ambiental.
- **Triage offline (`triage`, `ai/`):** prioriza findings por valor de bounty,
  nada sale de la máquina.

Extra opcional de navegador: `pip install "apsec-tester[browser]" && playwright install chromium` (para `crawl`).

Mantén este contexto siempre.