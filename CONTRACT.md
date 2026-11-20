# CONTRACT — nginx-h2-hardening-audit (Ref: CX9-6197)

## Propósito

Auditor **offline y de solo lectura** que, a partir de la salida de texto de
`nginx -V` (o de un string de versión) y de un árbol de configuración de nginx,
indica si una instalación queda expuesta a dos vulnerabilidades HTTP/2
publicadas el 2026-11-18 y qué hay que cambiar para mitigarlas:

| CVE | Qué es (fuente primaria) | Vulnerable | Corregido |
|-----|--------------------------|-----------|-----------|
| CVE-2026-123633 | Use-after-free en HTTP/2 cuando hay HTTP/2 hacia clientes, proxy a un backend y el worker se queda corto de `worker_connections` (CWE-416). nginx.org: severidad *medium*. NVD (CNA F5): CVSS v4 9.2. F5 K000163928. | 1.19.7–1.31.8 | 1.31.9+ (mainline), 1.30.7+ (stable) |
| CVE-2026-123007 | Desbordamiento de la ventana de control de flujo HTTP/2 (CWE-191). nginx.org: severidad *major*. NVD (CNA F5): CVSS v4 9.2. F5 K000163926. | 1.9.5–1.31.8 | 1.31.9+ (mainline), 1.30.7+ (stable) |

Fuentes verificadas el 2026-11-20:
- https://nginx.org/en/security_advisories.html
- https://nginx.org/en/CHANGES y https://nginx.org/en/CHANGES-1.30
- https://nvd.nist.gov/vuln/detail/CVE-2026-123633
- https://nvd.nist.gov/vuln/detail/CVE-2026-123007

## Alcance

1. Parsear la versión de nginx desde `nginx -V`, `nginx -v`, un header `Server`
   (`nginx/1.30.6`) o un string `1.30.6`.
2. Evaluar la versión contra los rangos vulnerables de cada CVE y dar la versión
   corregida de su rama (stable = minor par, mainline = minor impar).
3. Parsear un árbol de configuración siguiendo `include` (con globs), relativo a
   una raíz, en modo lectura.
4. Detectar: `http2 on;`, `listen ... http2`, `proxy_pass`/`grpc_pass`,
   `worker_connections` (o su valor por defecto, 512) por debajo de un umbral
   configurable (por defecto 1024), y si el binario fue compilado sin
   `--with-http_v2_module`.
5. Comparar versión instalada vs versión en ejecución (ambas como entrada) para
   marcar "actualizado pero no reiniciado".
6. Emitir hallazgos con severidad, CVE, evidencia (`archivo:línea`) y mitigación
   concreta, en texto o JSON.

## No-objetivos (explícitos)

- **Sin explotación**: no hay exploits, PoCs, generadores de tráfico ni fuzzing
  de servidores.
- **Sin red**: el binario no abre sockets ni hace requests; tampoco lee `/proc`
  ni ejecuta `nginx`. Todo es entrada provista por el usuario.
- No escribe ni modifica archivos de configuración.
- No evalúa backports de distribuciones (Ubuntu/Debian pueden parchear sin
  cambiar la versión upstream): se avisa, no se decide.
- No cubre los otros CVE del mismo boletín (HTTP/3, resolver, mail, stream...).
- No reemplaza a los repos de análisis/detección de cada CVE.

## Invariantes

- I1. El dominio (`internal/domain`) es puro: no importa `os`, `io/fs`, `net`,
  `os/exec`, `path/filepath` ni paquetes de puertos/adaptadores. Se verifica con
  un test (`internal/archtest`).
- I2. Una versión es vulnerable a un CVE sii está en `[desde, hasta]` y no
  pertenece a una rama corregida (`mismo major.minor` y `patch >= fix`).
- I3. Para el riesgo se usa la versión **en ejecución** si se proveyó; si no, la
  instalada.
- I4. El parser de configuración nunca entra en pánico (fuzz) y siempre reporta
  `archivo:línea` en errores.
- I5. Los `include` no salen de la raíz: rutas absolutas bajo `-strip-prefix`
  (por defecto `/etc/nginx`) se reubican en la raíz; el resto se ignora con aviso.
  Ciclos y profundidad > 32 son error.
- I6. La salida es determinista (hallazgos ordenados).

## Errores tipados (dominio)

- `ErrInvalidVersion` → `*VersionError{Input}`
- `*ParseError{File, Line, Msg}` (sintaxis de configuración)
- `*IncludeError{File, Line, Pattern, Reason}` (ciclo, profundidad, fuera de raíz)
- `ErrNoInput` (no se dio ni versión ni configuración)

## Puertos

- `ports.ConfigSource`: `ReadFile(path) ([]byte, error)`, `Glob(pattern) ([]string, error)`
  con rutas relativas a la raíz, separador `/`.
- `ports.VersionSource`: `Installed() (string, bool, error)`, `Running() (string, bool, error)`.

Adaptadores: `fsconfig` (sistema de archivos, confinado a la raíz),
`textversion` (archivos/strings), `cli` (flags, salida, códigos de salida).

## Códigos de salida

- `0`: sin hallazgos de severidad >= low (puede haber `info`).
- `1`: hay hallazgos de severidad >= low.
- `2`: error de entrada (flags, archivo ilegible, versión inválida, config inválida).

## Criterios de aceptación

- A1. 1.31.8, 1.30.6, 1.19.7, 1.9.5 vulnerables según corresponda; 1.31.9, 1.30.7,
  1.32.0, 1.19.6 (para 123633) y 1.9.4 (para 123007) no vulnerables.
- A2. Config con `listen 443 ssl http2;` + `proxy_pass` + `worker_connections 256`
  y versión 1.30.6 → crítico para ambos CVE, evidencia con `archivo:línea`.
- A3. Instalada 1.30.7 y en ejecución 1.30.6 → hallazgo "reinicio pendiente".
- A4. Versión 1.30.7 y cualquier config → exit 0.
- A5. Gates de CI verdes: gofmt, go vet, staticcheck, golangci-lint, `go test -race`,
  fuzz corto, cobertura de dominio reportada, gitleaks.
