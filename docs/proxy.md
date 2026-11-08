# Reverse proxy, Cloudflare і вхід для VPN

alertcast слухає лише loopback:

| Вхід | Типово | Для чого |
|---|---|---|
| публічний (`PUBLIC_LISTEN`) | `127.0.0.1:8790` | `https://alerts.example.com` — пристрої з будь-якої мережі |
| VPN (`VPN_LISTEN`) | вимкнено, напр. `127.0.0.1:8791` | `https://alerts-vpn.example.com` — API лише з VPN |
| адмінка (`ADMIN_LISTEN`) | `127.0.0.1:8793` | `https://alerts-admin.example.com` — **лише з VPN** (див. нижче) |
| локальний (`LOCAL_LISTEN`) | `127.0.0.1:8792` | `/health`, `/stats` — лише для цього сервера, ніколи не публікуйте |

Передавайте на alertcast **весь сайт**: alertcast сам віддає таблицю поточних тривог на `/`,
опис API на `/docs`, однакову 404 на все невідоме й API на `/api/…`.

## Справжня адреса клієнта

Від неї залежать обмеження токенів за адресою, ліміти й блокування підбору, тому кожен вхід
має власне правило (`*_IP_SOURCE`):

| Значення | Звідки адреса | Коли |
|---|---|---|
| `cf` | `CF-Connecting-IP`, але **лише** якщо до proxy з'єднався вузол Cloudflare (останній запис `X-Forwarded-For` — у мережах Cloudflare); інакше — адреса, з якої з'єднались з proxy | сайт за Cloudflare |
| `xff` | останній запис `X-Forwarded-For` — його дописує сам proxy | proxy без Cloudflare; VPN-сайт |
| `remote` | адреса TCP-з'єднання | без proxy |

Заголовкам alertcast вірить лише тоді, коли з'єднання прийшло з loopback (від вашого proxy).
Перевірка мереж Cloudflare в режимі `cf` захищає від випадку, коли публічний сайт доступний
ще й з VPN: тоді клієнт міг би підставити будь-який `CF-Connecting-IP`, але alertcast візьме
його справжню адресу в тунелі. Мережі Cloudflare вбудовані; змінити — `CF_RANGES`.

## Токени в журналах

Токен у заголовку `Authorization` proxy в журнал не пише. Токен у адресі (`?token=`, лише для
токенів з `--allow-query`) — пише, якщо не налаштовано інакше:

- **Caddy:** приберіть query з журналу фільтром або вимкніть журнал сайту:
  ```caddy
  alerts.example.com {
  	reverse_proxy 127.0.0.1:8790
  	log {
  		output file /var/log/caddy/alerts-access.log
  		format filter {
  			fields {
  				request>uri regexp \?.*$ ?…
  				request>headers>Authorization delete
  			}
  		}
  	}
  }
  ```
- **nginx:** у `log_format` пишіть `$uri` замість `$request_uri`.
- **VPN-вхід** токен у адресі не приймає взагалі (`VPN_ALLOW_QUERY=0`), бо журнали VPN-сайтів
  часто спільні й не фільтруються.

## Потоки (SSE)

- **Caddy** скидає `text/event-stream` одразу, тайм-аутів на довгі відповіді немає — нічого
  налаштовувати не треба.
- **nginx:** `proxy_buffering off; proxy_read_timeout 1h;` (alertcast також ставить
  `X-Accel-Buffering: no`).
- **Cloudflare** закриває з'єднання без даних через 100 с — alertcast шле `ping` кожні 15 с.
- Перезавантаження proxy може обірвати потоки — пристрої перепідключаються й отримують
  свіжий знімок, нічого не губиться.

## nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name alerts.example.com;
    ssl_certificate     /etc/letsencrypt/live/alerts.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/alerts.example.com/privkey.pem;

    log_format alertcast '$remote_addr [$time_local] "$request_method $uri" $status';
    access_log /var/log/nginx/alertcast.log alertcast;

    location / {
        proxy_pass http://127.0.0.1:8790;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
}
```

## Адмінка

Окремий сайт, доступний **лише з VPN**: адмінці не потрібна публічна адреса, а VPN — перший
рубіж перед паролем і 2FA. Окремий сайт (а не шлях на сайті API) — це окремі cookie, окремий
журнал proxy й окреме правило доступу.

- Адреса сервісу — `http://127.0.0.1:8793` (звичайний HTTP; HTTPS робить proxy). Сайт має бути
  на HTTPS: cookie входу має прапорець `Secure`.
- Proxy має передавати оригінальний `Host` (так роблять Caddy і nginx з `proxy_set_header Host
  $host`): зміни в адмінці приймаються лише з того самого `Origin`.
- `ADMIN_IP_SOURCE=xff`: адреса адміна для журналу й блокувань — з `X-Forwarded-For` від proxy.

```caddy
alerts-admin.example.com {
	@outside not remote_ip 10.8.0.0/24     # ваша мережа VPN
	respond @outside 404
	reverse_proxy 127.0.0.1:8793
}
```

Через Cloudflare адмінку не пропускайте (DNS-запис — **DNS only** або лише у VPN-DNS).

## Cloudflare

| Що | Значення |
|---|---|
| DNS | **Proxied** |
| SSL/TLS | **Full (strict)** |
| Security → Bots | Bot Fight Mode **вимкнений** — інакше пристрої отримують перевірку «чи ви людина» |
| WAF | правило **Skip** для `starts_with(http.request.uri.path, "/api/")`: managed rules, Browser Integrity Check, Security Level |

На сервері 443 має бути відкритий лише для [мереж Cloudflare](https://www.cloudflare.com/ips/).

## Перевірка

```bash
sudo alertcast check
curl -s https://alerts.example.com/ | grep '<h1>'                 # <h1>Тривоги зараз</h1>
curl -s https://alerts.example.com/api/v1/me                      # {"ok":false,"error":"unauthorized"}
curl -s -H "Authorization: Bearer ac_…" https://alerts.example.com/api/v1/me   # ваша адреса в "ip"
```

Поле `ip` у `/api/v1/me` показує, яку адресу бачить alertcast: це має бути справжня адреса
пристрою (на VPN-вході — адреса в тунелі), а не адреса Cloudflare чи `127.0.0.1`.
