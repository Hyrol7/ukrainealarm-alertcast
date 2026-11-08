# Супровід

## Стан

```bash
systemctl status alertcast
sudo alertcast check                    # служба, alertd, адмінка, публічна адреса
sudo alertcast token list               # хто й скільки звертається
curl -s localhost:8792/health           # 200 — дані свіжі; 503 — stale
curl -s localhost:8792/stats            # джерело, потоки, запити, блокування
```

| Поле `/stats` | Норма |
|---|---|
| `source.connected` | `true` |
| `source.stale` | `false` |
| `source.reconnects` / `resyncs` | поодинокі (перезапуски alertd) |
| `streams.total` | скільки пристроїв зараз на зв'язку |
| `requests.unauthorized` | поодинокі; багато — хтось підбирає або забули оновити токен на пристрої |
| `ipGuard.bans` | поодинокі |

Найзручніше — адмінка, розділ «Моніторинг»: стан alertcast і alertd, свіжість даних, потоки,
графіки затримок і запитів за 24 год, журнал, заблоковані адреси ([admin.md](admin.md)).
Публічна сторінка `/` — таблиця поточних тривог і позначка свіжості даних;
`https://<домен>/s` починається з `ok` — зручно для зовнішнього моніторингу.

## Зовнішній моніторинг

Служби перезапускаються самі — і коли падають, і коли зависають (сторожовий таймер systemd).
Але якщо недоступний увесь сервер, про це має сказати хтось ззовні. Найпростіше — безкоштовний
UptimeRobot (або Better Stack, Healthchecks тощо):

| Що | Значення |
|---|---|
| тип | HTTP(s) — Keyword |
| адреса | `https://alerts.example.com/s` (і так само `/s` сайту alertd) |
| ключове слово | `ok` — сповіщати, якщо **немає** |
| інтервал | 5 хв |
| сповіщення | e-mail, Telegram чи push у застосунку моніторингу |

`/s` відповідає `ok …`, лише коли зв'язок з alertd є й дані свіжі; `warn …` чи `bad …` — привід
глянути `sudo alertcast check`. Журнал не засмічується: `/s` можна виключити з журналу proxy.

## Звірка з ukrainealarm

```bash
sudo alertcast verify
```

```
Звірка з ukrainealarm (1 запит до API; alertd може пропустити одне своє опитування)…
✓ збігається: 214 регіонів зачеплено, 31 тривог (регіон+тип+рівні)
```

Один запит до `/api/v3/alerts` ukrainealarm (токен береться з `/etc/alertd/alertd.env`) і
порівняння з тим, що віддає alertcast: які регіони яких тривог стосуються і з якими рівнями.
Якщо щойно щось змінилось, команда перевіряє ще раз протягом ~70 с. Розбіжності, що лишаються,
виводяться поіменно — це привід розібратися. Ліміт ukrainealarm спільний з alertd, тож не
запускайте часто.

## Журнал

```bash
journalctl -u alertcast -f
journalctl -u alertcast --since today | grep -E "token|blocked|stale"
```

У журнал systemd пишуться старт, зв'язок з alertd, зміни токенів, блокування адрес, зміна
свіжості даних. Запити окремих пристроїв не пишуться (статистика — у `token list` і в адмінці).
Окремий журнал подій (входи в адмінку, зміни токенів, блокування, тестова область) — в адмінці,
зберігається 30 днів.

## Оновлення

```bash
sudo alertcast-update            # остання версія, якщо новіша
sudo alertcast-update 1.0.0      # конкретна версія (зокрема відкат)
```

Налаштування, токени, вхід в адмінку й БД не змінюються. Під час перезапуску потоки рвуться на ~0,1 с —
пристрої перепідключаються й отримують свіжий знімок.

## Резервна копія

```bash
sudo sqlite3 /var/lib/alertcast/alertcast.db ".backup '/root/alertcast-$(date +%F).db'"
sudo cp /etc/alertcast/alertcast.env /root/alertcast.env.backup
```

У БД — токени (хеші) зі статистикою, хеш пароля й секрет 2FA адміна, метрики за 24 год і
журнал подій. Стан тривог alertcast щоразу бере з alertd. Копію зберігайте так само закрито,
як `.env`.

## Діагностика

| Ознака | Що перевірити |
|---|---|
| `check`: `✗ alertd` | `systemctl status alertd`; `curl -s localhost:8788/health` |
| у відповідях `"stale": true` | alertd давно не звіряв стан з API ukrainealarm: `sudo alertd check` |
| пристрій отримує `401` | `sudo alertcast token show ID`: термін, адреси (`ip` у `/api/v1/me` — яку адресу бачить сервер), `--allow-query` |
| пристрій отримує `429` | ліміт токена (`--rpm`, `--streams`) або адресу заблоковано після невдалих спроб (чекати `Retry-After`) |
| у `/api/v1/me` поле `ip` — адреса Cloudflare чи `127.0.0.1` | правило адреси для входу: `PUBLIC_IP_SOURCE` / `VPN_IP_SOURCE` ([proxy.md](proxy.md)) |
| потоки рвуться щохвилини | буферизація чи тайм-аут proxy ([proxy.md](proxy.md#потоки-sse)) |
| загубили телефон з 2FA чи пароль | `sudo alertcast admin setup` — новий пароль і 2FA, усі сесії адміна завершуються |
| адмінка: «forbidden» на будь-яку зміну | proxy змінює `Host` — має передавати оригінальний ([proxy.md](proxy.md#адмінка)) |
| адмінка: вхід закрито для всіх на 5 хв | хтось у VPN підбирає пароль — див. журнал подій; `sudo alertcast admin logout` завершує всі сесії |

## Викрадений токен

```bash
sudo alertcast token revoke ID         # або rotate — новий секрет з тими самими правилами
```

Усі запити й потоки з ним припиняються одразу.

## Видалення

```bash
sudo systemctl disable --now alertcast
sudo rm -f /usr/local/bin/alertcast /usr/local/sbin/alertcast-update /etc/systemd/system/alertcast.service
sudo systemctl daemon-reload
sudo rm -rf /etc/alertcast /var/lib/alertcast
sudo userdel alertcast
```

І приберіть сайти з reverse proxy.
