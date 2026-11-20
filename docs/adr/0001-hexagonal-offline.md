# ADR 0001: arquitectura hexagonal y sin red

Estado: aceptado (2026-11-20). Ref: CX9-6197.

## Contexto
La herramienta se usa sobre servidores de producción durante un incidente. Tiene
que ser fácil de auditar y no puede, ni por accidente, generar tráfico.

## Decisión
- Dominio puro (versiones, rangos, parser, reglas) sin I/O; puertos
  `ConfigSource` y `VersionSource`; adaptadores de FS (confinado con `os.Root`),
  texto y CLI.
- Toda la información de ejecución (versión en ejecución, `nginx -V`) entra como
  texto provisto por el usuario. No se ejecuta `nginx`, no se lee `/proc`, no se
  abren sockets.
- La regla se hace cumplir con `internal/archtest` y `depguard` (prohíbe `net` y
  `os/exec` en todo el módulo).

## Consecuencias
- Se puede correr sobre una copia de `/etc/nginx` en una laptop.
- "Actualizado pero no reiniciado" depende de que el usuario pase la versión en
  ejecución (header `Server` o string); si `server_tokens off`, se informa que
  no se puede verificar.
