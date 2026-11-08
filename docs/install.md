# Перше розгортання

## 0. Що потрібно

- Сервер, на якому вже працює [alertd](https://github.com/Hyrol7/ukrainealarm-alertd)
  (перевірка: `curl -s localhost:8788/health` відповідає).
- Домен для пристроїв, напр. `alerts.example.com`, і reverse proxy з TLS (Caddy чи nginx).
- Для адмінки — домен, доступний лише через VPN, напр. `alerts-admin.example.com`.
- За бажанням — ще один домен лише для VPN для самого API, напр. `alerts-vpn.example.com`.

## 1. Встановити

Останню версію дивіться на сторінці [Releases](https://github.com/Hyrol7/ukrainealarm-alertcast/releases).

```bash
V=1.0.0
cd "$(mktemp -d)"
curl -fLO https://github.com/Hyrol7/ukrainealarm-alertcast/releases/download/v$V/alertcast-$V.tar.gz
curl -fLO https://github.com/Hyrol7/ukrainealarm-alertcast/releases/download/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify alertcast-$V.tar.gz --repo Hyrol7/ukrainealarm-alertcast   # необов'язково
tar xzf alertcast-$V.tar.gz && sudo ./alertcast/alertcast-install.sh
```

Скрипт створює користувача `alertcast`, ставить `/usr/local/bin/alertcast`,
`/usr/local/sbin/alertcast-update` і службу, створює `/etc/alertcast/alertcast.env` (права `600`)
і прибирає за собою пакет (`--keep` — залишити).

## 2. Налаштування

```bash
sudo nano /etc/alertcast/alertcast.env
```

| Що | Коли змінювати |
|---|---|
| `PUBLIC_URL=https://alerts.example.com` | завжди — для `alertcast check` |
| `PUBLIC_IP_SOURCE=cf` | `cf` — за Cloudflare; `xff` — proxy без Cloudflare; `remote` — без proxy |
| `VPN_LISTEN=127.0.0.1:8791` | якщо потрібен окремий вхід API лише для VPN |
| `ADMIN_LISTEN=127.0.0.1:8793` | типово ввімкнено; `off` — без адмінки |

Усі змінні — у [configuration.md](configuration.md).

## 3. Reverse proxy

| Сайт | Куди | Доступ |
|---|---|---|
| `alerts.example.com` | `127.0.0.1:8790` | публічно |
| `alerts-admin.example.com` | `127.0.0.1:8793` | **лише VPN** |
| `alerts-vpn.example.com` (за бажанням) | `127.0.0.1:8791` | лише VPN |

Передавайте весь сайт, адресу сервісу — звичайним `http://` (TLS робить proxy). Для Caddy:

```caddy
alerts.example.com {
	reverse_proxy 127.0.0.1:8790
}

# адмінка — лише з мережі VPN (тут 10.8.0.0/24)
alerts-admin.example.com {
	@outside not remote_ip 10.8.0.0/24
	respond @outside 404
	reverse_proxy 127.0.0.1:8793
}
```

Потоки SSE Caddy пропускає без буферизації сам. Як не писати токени в журнали, nginx і
Cloudflare — у [proxy.md](proxy.md).

## 4. Запуск, вхід в адмінку, перевірка

```bash
sudo systemctl start alertcast
sudo alertcast admin setup
```

`admin setup` питає пароль (від 12 символів) і показує QR для застосунку 2FA (Google
Authenticator, Aegis, 1Password…); зберігає лише після правильного коду з застосунку.
Детальніше — [admin.md](admin.md).

```bash
sudo alertcast check
```

```
✓ служба           alertcast 1.0.0 працює 3s, токенів 0, потоків 0
✓ alertd           потік відкритий, регіонів 1606, активних тривог 52, звірка 2026-11-08T14:09:28Z
✓ адмінка          слухає 127.0.0.1:8793, вхід налаштовано (пароль + 2FA)
✓ публічна адреса  ланцюжок до alertcast працює (запит без токена отримав 401 від alertcast)
```

## 5. Перший токен і перевірка ззовні

Створіть токен в адмінці (`https://alerts-admin.example.com` → Токени → Новий токен) або з консолі:

```bash
sudo alertcast token add --name "Мій телефон" --regions 32
curl -H "Authorization: Bearer ac_…" "https://alerts.example.com/api/v1/status?regions=32"
curl -N -H "Authorization: Bearer ac_…" "https://alerts.example.com/api/v1/stream?regions=32"
```

ID свого регіону знайдіть у `/api/v1/regions`. Повний опис API з кнопками «Виконати» —
`https://alerts.example.com/docs`. Готово — далі [tokens.md](tokens.md) і [maintenance.md](maintenance.md).
