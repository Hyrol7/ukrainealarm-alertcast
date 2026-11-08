# ukrainealarm-alertcast — API повітряних тривог для пристроїв

Ваш власний API тривог України для будь-яких пристроїв: ESP8266/ESP32, телефонів, ботів, сайтів.
Бере стан і зміни з [ukrainealarm-alertd](https://github.com/Hyrol7/ukrainealarm-alertd),
рахує стан кожного регіону з урахуванням ієрархії (громада → район → область) і віддає його
за токенами з вашими обмеженнями.

```
ukrainealarm ──webhook──► alertd ──/state, /events (loopback)──► alertcast ──► reverse proxy (TLS)
                                                                    │         ├─ https://alerts.example.com        публічно: API, /docs, таблиця тривог
                                              sudo alertcast token ─┘         ├─ https://alerts-vpn.example.com    лише VPN: API
                                                                              └─ https://alerts-admin.example.com  лише VPN: адмінка (пароль + 2FA)
                                                                                    │
                                                                    ESP8266/ESP32, телефони, боти, браузер
```

- **Миттєво:** зміна доходить до тисячі відкритих потоків за ~15 мс; запит стану — мікросекунди.
- **Надійно:** після будь-якого обриву пристрій отримує свіжий знімок — зміну неможливо
  загубити; повільний клієнт нікого не гальмує; коли джерело недоступне, віддається останній
  стан з позначкою `stale`.
- **Безпечно:** токени (у БД лише хеш) з лімітами запитів і потоків, терміном дії, дозволеними
  регіонами й адресами; блокування підбору; справжня адреса клієнта, яку не підробити
  заголовком; керування лише root через локальний сокет; служба не може з'єднатися ні з чим,
  крім цього сервера (`systemd-analyze security`: 0.9). Деталі — [docs/security.md](docs/security.md).
- **Зручно:** вебадмінка через VPN (пароль + 2FA): токени з QR-кодом, моніторинг затримок,
  потоків і запитів за 24 год, журнал, тестова область для перевірки пристроїв. Опис API з
  кнопками «Виконати» — на самому сервері, `/docs`.
- **Сумісно:** окрім власного компактного формату — ті самі `/api/v3/alerts…`, що в
  ukrainealarm: готові прошивки працюють, якщо змінити лише адресу й токен.

## Швидкий старт

Потрібен працюючий alertd на тому самому сервері.

```bash
V=1.0.0
cd "$(mktemp -d)"
curl -fLO https://github.com/Hyrol7/ukrainealarm-alertcast/releases/download/v$V/alertcast-$V.tar.gz
curl -fLO https://github.com/Hyrol7/ukrainealarm-alertcast/releases/download/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar xzf alertcast-$V.tar.gz && sudo ./alertcast/alertcast-install.sh   # після встановлення пакет видаляється

sudo nano /etc/alertcast/alertcast.env      # PUBLIC_URL, за потреби VPN_LISTEN
# reverse proxy з HTTPS: публічний сайт → 127.0.0.1:8790, адмінка (лише VPN) → 127.0.0.1:8793 — docs/proxy.md
sudo systemctl start alertcast
sudo alertcast admin setup                  # пароль і 2FA для адмінки
sudo alertcast check
sudo alertcast token add --name "Мій телефон" --regions 32   # або в адмінці
```

```bash
curl -H "Authorization: Bearer ac_…" "https://alerts.example.com/api/v1/status?regions=32"
```

## Документація

| Файл | Що |
|---|---|
| [docs/api.md](docs/api.md) | **API для пристроїв**: токени, стан, потік, помилки, сумісність з ukrainealarm, приклади (інтерактивно — `/docs` на сервері) |
| [docs/install.md](docs/install.md) | перше розгортання крок за кроком |
| [docs/tokens.md](docs/tokens.md) | керування токенами й обмеженнями |
| [docs/admin.md](docs/admin.md) | вебадмінка: доступ через VPN, пароль + 2FA, що в ній є |
| [docs/maintenance.md](docs/maintenance.md) | супровід: оновлення, моніторинг, діагностика, видалення |
| [docs/proxy.md](docs/proxy.md) | Caddy, nginx, Cloudflare; окремий вхід для VPN |
| [docs/security.md](docs/security.md) | модель загроз і захист |
| [docs/configuration.md](docs/configuration.md) | усі змінні `alertcast.env` |
| [docs/development.md](docs/development.md) | збірка, тести, релізи |
| [ROADMAP.md](ROADMAP.md) | що далі |

## Ліцензія

[MIT](LICENSE). Проєкт не пов'язаний з ukrainealarm.com; дані належать їхнім власникам,
користуйтеся відповідно до умов їхнього API.
