# Guía de hardening: CVE-2026-123007 y CVE-2026-123633 (nginx HTTP/2)

Guía para droplets Ubuntu/Debian. Todo lo de acá es defensivo: actualizar,
reiniciar, verificar y monitorear.

## 1. ¿Estoy afectado?

| CVE | Vulnerable | Corregido | Condición |
|-----|-----------|-----------|-----------|
| CVE-2026-123007 (flow control HTTP/2, CWE-191; nginx.org: major) | 1.9.5–1.31.8 | 1.31.9 / 1.30.7 | HTTP/2 habilitado |
| CVE-2026-123633 (use-after-free HTTP/2, CWE-416; nginx.org: medium) | 1.19.7–1.31.8 | 1.31.9 / 1.30.7 | HTTP/2 hacia clientes + proxy a backend + worker corto de `worker_connections` |

NVD publica para ambos el puntaje del CNA (F5): CVSS v4 9.2. nginx.org califica
CVE-2026-123633 como *medium*; las dos cosas son ciertas y miden cosas distintas.

```sh
nginx -V 2>&1 | tee nginx-V.txt          # versión instalada + módulos
sudo cp -r /etc/nginx ./nginx-snapshot   # copia de solo lectura de la config
nginx-h2-audit -nginx-v nginx-V.txt -config-root ./nginx-snapshot
```

## 2. Actualizar con los paquetes de nginx.org

Las versiones de los repos de Ubuntu/Debian suelen ser ramas viejas (p. ej.
1.24.x) que **no** reciben fix upstream; la distro puede backportear el parche
sin cambiar el número. Revisá su tracker de seguridad o pasá a los paquetes
oficiales (instrucciones de https://nginx.org/en/linux_packages.html):

```sh
sudo apt install curl gnupg2 ca-certificates lsb-release ubuntu-keyring   # Debian: debian-archive-keyring
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
  | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
gpg --dry-run --quiet --no-keyring --import --import-options import-show \
  /usr/share/keyrings/nginx-archive-keyring.gpg
# Debe mostrar la huella 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62

# stable (1.30.x); para mainline usar .../packages/mainline/ubuntu
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
https://nginx.org/packages/ubuntu `lsb_release -cs` nginx" \
  | sudo tee /etc/apt/sources.list.d/nginx.list
echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
  | sudo tee /etc/apt/preferences.d/99nginx

sudo apt update
sudo apt install nginx
```

Antes de cambiar de origen de paquetes hacé backup de `/etc/nginx`: el paquete
de nginx.org usa `conf.d/` y no trae `sites-enabled/` por defecto.

## 3. Reinicio completo (no reload)

`nginx -s reload` / `systemctl reload nginx` relee la configuración pero el
proceso master sigue siendo el binario viejo. Después de actualizar:

```sh
sudo nginx -t
sudo systemctl restart nginx
nginx -v                                   # versión instalada
curl -sI https://TU-DOMINIO/ | grep -i '^server:'   # versión en ejecución (si server_tokens on)
nginx-h2-audit -nginx-v nginx-V.txt -running "Server: nginx/1.30.7"
```

Si la versión instalada y la que responde no coinciden, la regla
`RESTART-PENDING` lo marca.

## 4. Mitigación temporal si no podés actualizar ya

```nginx
# por server o en http {}
http2 off;
# y quitar "http2" de las líneas listen:
listen 443 ssl;          # antes: listen 443 ssl http2;
```

Luego `sudo nginx -t && sudo systemctl reload nginx`. Esto sacrifica HTTP/2
(los clientes caen a HTTP/1.1). Subir `worker_connections` (y
`worker_rlimit_nofile`) reduce la condición de CVE-2026-123633 pero **no** la
corrige.

## 5. Monitoreo

- Workers que mueren: `sudo grep -E "exited on signal (11|6)|worker process .* exited" /var/log/nginx/error.log`
- Falta de conexiones: `grep "worker_connections are not enough" /var/log/nginx/error.log`
- Reinicios del servicio: `journalctl -u nginx --since "-24h"`
- Alertar si aparecen de forma repetida (p. ej. con una regla de fail2ban,
  Loki/Promtail o un cron que cuente ocurrencias por hora).
- Tras actualizar, volver a correr `nginx-h2-audit` en CI/cron con la salida de
  `nginx -V` para que una regresión de versión no pase desapercibida.

## Fuentes primarias

- nginx security advisories: https://nginx.org/en/security_advisories.html
- nginx CHANGES (1.31.9): https://nginx.org/en/CHANGES
- nginx CHANGES-1.30 (1.30.7): https://nginx.org/en/CHANGES-1.30
- NVD CVE-2026-123007: https://nvd.nist.gov/vuln/detail/CVE-2026-123007
- NVD CVE-2026-123633: https://nvd.nist.gov/vuln/detail/CVE-2026-123633
- F5 K000163926: https://my.f5.com/manage/s/article/K000163926
- F5 K000163928: https://my.f5.com/manage/s/article/K000163928
- Paquetes oficiales: https://nginx.org/en/linux_packages.html
