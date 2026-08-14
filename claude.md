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

Mantén este contexto siempre.