# nginx-h2-hardening-audit

[![ci](https://github.com/federiconbaez/nginx-h2-hardening-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/federiconbaez/nginx-h2-hardening-audit/actions/workflows/ci.yml)

Auditor **offline y de solo lectura**, escrito en Go, que te dice si tu nginx
queda expuesto a dos vulnerabilidades HTTP/2 publicadas el 18/11/2026 y qué
cambiar para cerrarlas. Es complementario a los repos de análisis y detección
de cada CVE: este se enfoca en **tu versión y tu configuración**.

| CVE | Vulnerable | Corregido | Fuente |
|-----|-----------|-----------|--------|
| CVE-2026-123007 — corrupción de memoria en flow control HTTP/2 (CWE-191; nginx.org: *major*; NVD/F5: CVSS v4 9.2) | 1.9.5–1.31.8 | 1.31.9 (mainline), 1.30.7 (stable) | [nginx.org](https://nginx.org/en/security_advisories.html), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-123007), [F5 K000163926](https://my.f5.com/manage/s/article/K000163926) |
| CVE-2026-123633 — use-after-free en HTTP/2 con proxy y `worker_connections` insuficientes (CWE-416; nginx.org: *medium*; NVD/F5: CVSS v4 9.2) | 1.19.7–1.31.8 | 1.31.9 (mainline), 1.30.7 (stable) | [nginx.org](https://nginx.org/en/security_advisories.html), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-123633), [F5 K000163928](https://my.f5.com/manage/s/article/K000163928) |

Rangos verificados el 20/11/2026 contra nginx.org (advisories, `CHANGES` y
`CHANGES-1.30`) y NVD.

## Qué chequea

- **VULNERABLE-VERSION**: versión en rango vulnerable por CVE, con la versión
  corregida de tu rama (stable = minor par, mainline = minor impar) o aviso de
  que tu rama no tiene fix upstream.
- **HTTP/2 habilitado**: `http2 on;` y `listen ... http2`, con `archivo:línea`.
- **LOW-WORKER-CONNECTIONS**: `proxy_pass`/`grpc_pass` + HTTP/2 +
  `worker_connections` por debajo del umbral (1024 por defecto, `-wc-threshold`;
  si no está definido se asume el default de nginx, 512). El umbral es una
  heurística propia, no sale del advisory.
- **RESTART-PENDING**: versión instalada (`nginx -V`) distinta de la versión en
  ejecución (header `Server` o string que le pases) → "actualizado pero no
  reiniciado".
- **H2-MODULE-ABSENT**, **DISTRO-PACKAGE**, **RUNNING-VERSION-HIDDEN**,
  **H2-ENABLED-VERSION-UNKNOWN**: avisos de contexto.

Cada hallazgo trae severidad (contextual, ver
[ADR 0002](docs/adr/0002-severidad-contextual.md)), CVE, evidencia y mitigación:
actualizar + **reinicio completo** (no reload); si no se puede, `http2 off;`.

## Qué NO hace

- No explota nada, no genera tráfico, no abre sockets, no ejecuta `nginx` ni lee
  `/proc` (forzado por `internal/archtest` y `depguard`).
- No decide sobre backports de distros (Ubuntu/Debian): lo avisa.
- No cubre otros CVE del mismo boletín (HTTP/3, resolver, mail, stream).
- No interpreta `$variables`, `if`, ni módulos de terceros; solo lee directivas.
- Includes absolutos fuera de `-strip-prefix` (por defecto `/etc/nginx`) se
  ignoran con aviso.

## Uso

```sh
go install github.com/federiconbaez/nginx-h2-hardening-audit/cmd/nginx-h2-audit@latest

# en el servidor (solo lectura):
nginx -V > nginx-V.txt 2>&1
nginx-h2-audit -nginx-v nginx-V.txt -config-root /etc/nginx

# o por stdin, sin archivo intermedio:
nginx -V 2>&1 | nginx-h2-audit -nginx-v - -config-root /etc/nginx

# o sobre una copia, con la versión que responde el servidor:
nginx-h2-audit -nginx-v nginx-V.txt -config-root ./nginx-snapshot \
  -running "Server: nginx/1.30.6" -format json
```

| Flag | Descripción |
|------|-------------|
| `-nginx-v FILE` | salida de `nginx -V` (`-` = stdin) |
| `-version 1.30.6` | alternativa a `-nginx-v` |
| `-running STR` / `-running-file FILE` | versión en ejecución o header `Server` |
| `-config-root DIR` | raíz del árbol de config (se abre con `os.Root`) |
| `-config-main nginx.conf` | archivo principal relativo a la raíz |
| `-strip-prefix /etc/nginx` | prefijo de includes absolutos que se reubica en la raíz |
| `-wc-threshold 1024` | umbral de `worker_connections` |
| `-format text\|json` | salida |

Códigos de salida: `0` sin hallazgos (o solo `info`), `1` hallazgos ≥ `low`,
`2` error de entrada.

Ejemplo real sobre `testdata/fixtures/vuln-proxy` (salida completa en
`expected.txt`):

```
[CRITICAL] VULNERABLE-VERSION: CVE-2026-123633: Use-after-free in HTTP/2 (nginx.org: medium, CVSSv4 9.2, CWE-416)
  evidence: installed version 1.30.6 (stable branch) in vulnerable range 1.19.7-1.31.8
  evidence: conf.d/mcp.conf:3 listen 443 ssl http2
  evidence: conf.d/mcp.conf:6 proxy_pass
  evidence: nginx.conf:5 worker_connections 256 (threshold 1024)
  mitigation: upgrade to 1.30.7 (stable branch), then full restart (`sudo systemctl restart nginx`, not reload) ...
```

Guía de actualización y monitoreo: [docs/HARDENING.md](docs/HARDENING.md).

## Arquitectura

Hexagonal ([CONTRACT.md](CONTRACT.md), [ADR 0001](docs/adr/0001-hexagonal-offline.md)):

```
cmd/nginx-h2-audit → adapters/cli → app → domain (puro)
                     adapters/fsconfig, adapters/textversion → ports
```

- `internal/domain`: versiones, rangos, parser de config, reglas. Sin I/O.
- `internal/ports`: `ConfigSource`, `VersionSource` + suite de contrato (`porttest`).
- `internal/app`: resolución de `include` (globs, ciclos, profundidad ≤ 32, confinado a la raíz).
- `internal/adapters`: FS, texto, CLI.

## Calidad (números medidos)

Gates en CI: gofmt, go vet, staticcheck, golangci-lint (con depguard y gosec),
`go test -race`, fuzz corto, cobertura de dominio, gitleaks.

Medido localmente el 20/11/2026:

- 36 tests de nivel superior y 80 subtests, todos en verde con `-race`.
- Cobertura del paquete `internal/domain`: **96,6 %** de sentencias
  (todo `internal/...`: 96,1 %).
- Fuzz: `FuzzParseConfig` 20 s, ~6,1 M ejecuciones sin fallos;
  `FuzzParseVersion` 15 s sin fallos.
- Tests de propiedades (`testing/quick`, 5000 casos cada uno): orden de
  versiones antisimétrico y transitivo, ida y vuelta `String`/`Parse`,
  fronteras de rango por rama.

## Cómo contarlo en una entrevista

- **Problema**: dos CVE HTTP/2 en nginx con distinta precondición; la pregunta
  real en un incidente es "¿*mi* servidor está expuesto y qué toco primero?".
- **Decisión clave**: offline y por entrada de texto. Se puede correr en medio
  de un incidente sin riesgo de generar tráfico ni tocar producción; la regla
  está forzada por tests de arquitectura, no por buena voluntad.
- **Detalle técnico interesante**: los rangos no son un intervalo simple —
  1.30.7 está corregido pero 1.31.0–1.31.8 no; se modela como "en rango y no en
  una rama corregida", con tests de propiedades en las fronteras.
- **Trampa operativa**: actualizar el paquete y hacer `reload` deja corriendo el
  binario viejo; por eso existe `RESTART-PENDING`.
- **Honestidad**: el umbral de `worker_connections` es heurístico y las distros
  pueden backportear; la herramienta lo dice en vez de esconderlo.

## Licencia

Apache-2.0. Ver [LICENSE](LICENSE).
