# Налаштування

Файл `/etc/alertcast/alertcast.env` (права `600`, власник root). Після змін —
`sudo systemctl restart alertcast`. Некоректні значення не дадуть службі стартувати; причина —
у `journalctl -u alertcast`.

| Змінна | Типово | Що |
|---|---|---|
| `ALERTD_URL` | `http://127.0.0.1:8788` | локальний API alertd (http — лише loopback) |
| `PUBLIC_LISTEN` | `127.0.0.1:8790` | публічний вхід (за reverse proxy) |
| `PUBLIC_IP_SOURCE` | `cf` | звідки адреса клієнта: `cf`, `xff`, `remote` (див. [proxy.md](proxy.md)) |
| `VPN_LISTEN` | вимкнено | окремий вхід лише для VPN, напр. `127.0.0.1:8791` |
| `VPN_IP_SOURCE` | `xff` | звідки адреса клієнта на VPN-вході |
| `VPN_ALLOW_QUERY` | `0` | `1` — приймати `?token=` і на VPN-вході |
| `ADMIN_LISTEN` | `127.0.0.1:8793` | адмінка, лише loopback; `off` — вимкнено (див. [admin.md](admin.md)) |
| `ADMIN_IP_SOURCE` | `xff` | звідки адреса адміна (для журналу й блокувань) |
| `LOCAL_LISTEN` | `127.0.0.1:8792` | `/health`, `/stats`; лише loopback |
| `PUBLIC_URL` | — | публічна адреса для `alertcast check` і QR-коду нового токена |
| `STALE_AFTER` | `5m` | через скільки без підтвердження з API ukrainealarm дані позначаються `stale` |
| `DEFAULT_RPM` | `60` | типовий ліміт запитів на хвилину для нового токена |
| `DEFAULT_STREAMS` | `2` | типова кількість одночасних потоків для нового токена |
| `MAX_STREAMS` | `2000` | потоків загалом |
| `MAX_STREAMS_PER_IP` | `20` | потоків з однієї адреси |
| `IP_RPM` | `300` | запитів на хвилину з однієї адреси (до перевірки токена) |
| `AUTH_FAIL_LIMIT` | `10` | невдалих спроб автентифікації до блокування адреси |
| `AUTH_FAIL_WINDOW` | `10m` | за який час рахуються спроби |
| `AUTH_BAN` | `15m` | на скільки блокується адреса |
| `MAX_REGIONS` | `64` | регіонів в одному запиті |
| `SITE_TITLE` | порожньо | назва вкладки на публічних сторінках |
| `CF_RANGES` | вбудовані | мережі Cloudflare через кому (якщо Cloudflare їх змінить) |
| `DB_PATH` | `/var/lib/alertcast/alertcast.db` | БД токенів |
| `ADMIN_SOCKET` | `/run/alertcast/admin.sock` | сокет керування |
| `ENV_FILE` | `/etc/alertcast/alertcast.env` | звідки ручні команди беруть налаштування |

Тривалості — у форматі Go (`90s`, `5m`, `1h`) або числом секунд.

Якщо `VPN_LISTEN` слухає не loopback, а адресу VPN (напр. `10.77.0.1:8791`, без proxy), додайте
цю мережу в unit: `sudo systemctl edit alertcast` →
```ini
[Service]
IPAddressAllow=localhost 10.77.0.0/24
```
і поставте `VPN_IP_SOURCE=remote`.
