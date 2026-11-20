# ADR 0002: severidad contextual por configuración

Estado: aceptado (2026-11-20). Ref: CX9-6197.

## Contexto
nginx.org califica CVE-2026-123007 como *major* y CVE-2026-123633 como *medium*;
NVD (CNA F5) asigna CVSS v4 9.2 a ambos. Ninguna de las dos escalas sabe si el
servidor tiene HTTP/2 o proxy.

## Decisión
La severidad del hallazgo combina versión y configuración:

| Situación | 123007 | 123633 |
|-----------|--------|--------|
| Versión vulnerable, sin config | high | high |
| HTTP/2 activo | critical | low si no hay proxy |
| HTTP/2 + proxy | critical | high |
| HTTP/2 + proxy + `worker_connections` < umbral | critical | critical |
| HTTP/2 no habilitado / módulo ausente | low | low |

El umbral (1024 por defecto, configurable con `-wc-threshold`) es heurístico:
el advisory no define un número. Si no hay `worker_connections`, se usa el
default de nginx (512). Se muestran siempre la calificación de nginx.org y el
CVSS para no esconder la fuente.

## Consecuencias
Un `low` sigue haciendo salir con código 1: la versión es vulnerable aunque la
config actual no lo exponga, y la config puede cambiar.
