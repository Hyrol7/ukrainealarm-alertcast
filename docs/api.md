# API для пристроїв

> Інтерактивна версія цього опису (з кнопками «Виконати») — на самому сервері: `https://<ваш-сайт>/docs`.

Базова адреса — ваш сервер, напр. `https://alerts.example.com`. Усі запити — `GET`,
відповіді — JSON (UTF-8). Кожен запит потребує токена.

## Токен

Токен видає власник сервера (`sudo alertcast token add …`). Вигляд: `ac_` і 43 символи.
Передавайте його одним зі способів:

| Спосіб | Приклад |
|---|---|
| заголовок (рекомендовано) | `Authorization: Bearer ac_…` |
| як в ukrainealarm | `Authorization: ac_…` |
| окремий заголовок | `X-API-Key: ac_…` |
| у адресі — лише якщо токен створено з `--allow-query` | `?token=ac_…` |

Токен у адресі потрапляє в журнали проміжних серверів, тому використовуйте його лише там, де
заголовки неможливі. Для браузера краще — сесія (нижче).

### Браузер: сесія замість токена в адресі

Сторінка один раз надсилає токен у заголовку й отримує захищену cookie; далі браузер, зокрема
`EventSource`, працює з нею — токен не потрапляє ні в адресу, ні в журнали.

```js
await fetch("/api/v1/session", {method: "POST", headers: {Authorization: `Bearer ${token}`}});
const es = new EventSource("/api/v1/stream?regions=32");   // cookie додається сама
// вихід: await fetch("/api/v1/session", {method: "DELETE"});
```

- cookie `__Host-ac_session`: `HttpOnly` (недоступна скриптам), `Secure`, `SameSite=Strict`
  (не надсилається з чужих сайтів), діє 12 год;
- увійти можна лише токеном у заголовку (не `?token=`, не іншою сесією); запит з чужого
  `Origin` відхиляється;
- сесія має ті самі обмеження, що й токен (регіони, адреси, ліміти, термін); зміна, `rotate`
  чи відкликання токена одразу гасять усі його сесії;
- сесії живуть у пам'яті служби: після її перезапуску сторінка просто входить знову
  (`401` → повторити `POST /api/v1/session`).

## Регіони

ID регіонів — як в ukrainealarm: область, район, громада. Повний список із назвами:

```
GET /api/v1/regions
```
```json
{"ok":true,"regions":[
 {"id":"4","name":"Вінницька область","type":"State"},
 {"id":"32","name":"Вінницький район","type":"District","parent":"4","state":"4"},
 {"id":"1234","name":"Вінницька територіальна громада","type":"Community","parent":"32","state":"4"}]}
```

Відповідь має `ETag` — повторний запит з `If-None-Match` поверне `304` без тіла. Список
змінюється рідко: тримайте його в кеші пристрою.

## Стан регіонів

```
GET /api/v1/status?regions=32,4
```

`regions` — до 64 ID через кому. Без параметра — регіони, закріплені за токеном.

```json
{"ok":true,"stale":false,"verifiedAt":"2026-11-08T13:20:05Z","version":4182,
 "regions":{
  "32":{"id":"32","name":"Вінницький район","type":"District","state":"active","level":"red",
        "since":"2026-11-08T13:01:10Z",
        "types":{"AIR":{"state":"active","levels":["red","yellow"],"since":"2026-11-08T13:01:10Z","from":["32"]}}},
  "4": {"id":"4","name":"Вінницька область","type":"State","state":"partial","level":"red",
        "types":{"AIR":{"state":"partial","levels":["red","yellow"],"partial":["32"]}}}}}
```

| Поле | Значення |
|---|---|
| `state` | `active` — тривога діє в регіоні; `partial` — лише в частині вкладених регіонів; `none` — спокій |
| `level` | найвищий рівень: `red` — ракетна небезпека, `yellow` — загроза БпЛА, `unknown` — не вказано; немає при `none` |
| `since` | початок тривоги (для `active`) |
| `types` | окремо для кожного типу тривоги: `AIR`, `ARTILLERY`, `URBAN_FIGHTS`, `CHEMICAL`, `NUCLEAR`, … Порожній `{}` при `none` |
| `types.*.levels` | усі чинні рівні, від найвищого — вони бувають одночасно |
| `types.*.from` | де оголошено: сам регіон або його предок (напр. уся область) |
| `types.*.partial` | вкладені регіони з тривогою |
| `stale` | `true` — сервер давно не підтверджував стан з джерелом; показуйте «немає зв'язку» або останній стан з позначкою |
| `verifiedAt` | коли стан востаннє підтверджено повним знімком ukrainealarm |

**Як рахується стан.** Громада — `active`, якщо тривогу оголошено для неї, її району або
області. Район — `active`, якщо тривогу оголошено для нього або області; `partial`, якщо
лише для частини його громад. Область — `active`, якщо для всієї області; `partial`, якщо
лише для частини районів чи громад.

## Потік змін (рекомендовано)

```
GET /api/v1/stream?regions=32,4
```

Server-Sent Events: одне довге HTTPS-з'єднання, зміни приходять миттєво.

```
retry: 2847

event: snapshot
data: {"ok":true,"stale":false,…,"regions":{…}}       ← те саме, що /api/v1/status

event: update
data: {"version":4183,"region":{…стан одного регіону…}}

event: meta
data: {"stale":true,"verifiedAt":"…"}                 ← змінилась свіжість даних

: ping                                                ← кожні 15 с

event: bye
data: {"reason":"token changed"}                      ← токен змінено чи відкликано
```

- Після кожного підключення спершу приходить `snapshot` — повний стан запитаних регіонів.
  Тому після обриву просто перепідключіться: ви отримаєте актуальний стан, нічого не загубиться.
- `update` приходить лише тоді, коли змінився **стан регіону** (не на кожну подію в країні).
  Проміжні зміни, що сталися між двома відправками, можуть злитися — ви завжди отримуєте
  останній стан.
- Якщо 45 с не надходить нічого (навіть `ping`) — з'єднання мертве, перепідключіться.
- `retry` — рекомендована затримка перепідключення (1–5 с, випадкова).

**Затримка.** alertcast передає зміну за мілісекунди, але сама подія приходить від ukrainealarm
із затримкою: зазвичай 2–10 с, зрідка до хвилини. Якщо webhook загубився, зміну підбирає
звірка з API ukrainealarm — не пізніше ніж за ~1 хв.

## Помилки

```json
{"ok":false,"error":"unauthorized"}
```

| Код | Коли | Що робити |
|---|---|---|
| `400` | некоректний чи невідомий регіон, забагато регіонів | виправити запит |
| `401` | немає токена, невідомий, прострочений, з недозволеної адреси, у адресі без дозволу | перевірити токен (причину навмисно не уточнюємо) |
| `403` | регіон поза дозволеними для токена | — |
| `429` | ліміт запитів чи потоків; або адресу тимчасово заблоковано після невдалих спроб | чекати `Retry-After` секунд |
| `503` | сервер щойно запустився або забагато потоків загалом | повторити за `Retry-After` |

## Сумісність з ukrainealarm API v3

Для готових прошивок і бібліотек: замініть адресу `https://api.ukrainealarm.com` на свою і
токен ukrainealarm на свій.

| Запит | Як в ukrainealarm |
|---|---|
| `GET /api/v3/alerts` | усі регіони з тривогою (лише дозволені токену) |
| `GET /api/v3/alerts/{regionId}` | масив з одного запису для регіону |
| `GET /api/v3/alerts/status` | `{"lastActionIndex": N}` — зростає з кожною зміною |
| `GET /api/v3/regions` | дерево регіонів |

Семантика оригінальна: запис регіону містить тривоги, оголошені для нього, його предків і
вкладених регіонів, кожна зі своїм `regionId`. Якщо дані застаріли, відповідь має заголовок
`X-Data-Stale: 1`.

## Інше

```
GET /api/v1/me
```
Налаштування вашого токена: ліміти, дозволені регіони й мережі, відкриті потоки, ваша адреса
очима сервера.

## Приклади

**curl:**
```bash
curl -H "Authorization: Bearer $TOKEN" "https://alerts.example.com/api/v1/status?regions=32"
curl -N -H "Authorization: Bearer $TOKEN" "https://alerts.example.com/api/v1/stream?regions=32"
```

**Браузер** (через сесію, див. вище; або токен з `--allow-query` у адресі):
```js
await fetch("/api/v1/session", {method: "POST", headers: {Authorization: `Bearer ${token}`}});
const es = new EventSource("/api/v1/stream?regions=32");
es.addEventListener("snapshot", e => render(JSON.parse(e.data).regions));
es.addEventListener("update", e => update(JSON.parse(e.data).region));
es.addEventListener("meta", e => setStale(JSON.parse(e.data).stale));
```

**Python:**
```python
import json, requests
with requests.get(URL + "/api/v1/stream", params={"regions": "32"},
                  headers={"Authorization": f"Bearer {TOKEN}"}, stream=True, timeout=(10, 45)) as r:
    event = None
    for line in r.iter_lines(decode_unicode=True):
        if line.startswith("event: "):
            event = line[7:]
        elif line.startswith("data: ") and event in ("snapshot", "update"):
            print(event, json.loads(line[6:]))
```

**ESP8266 / ESP32:** найпростіше — раз на 10–30 с запитувати
`/api/v1/status?regions=…` (у межах ліміту токена) і реагувати на `state` і `level` —
готовий скетч для ESP8266 (ESP-12F) є на сторінці `/docs`, вкладка «Приклади коду»; для
миттєвої реакції — читати `/api/v1/stream` построково з тайм-аутом 45 с і перепідключенням.
