# bnat

Self-hosted reverse proxy, чтобы достучаться до машин за NAT: SSH, HTTP и сырой TCP. Один бинарь, админка в браузере.

```
                         ┌──────────── VPS ────────────┐
ssh -p 21028 tun.bnat… ─▶│ :20000-29999 ─┐             │      ┌── машина за NAT ──┐
https://app.bnat…     ─▶│ :443 ─────────┼─ yamux/wss ─┼─────▶│ bnat ssh / http   │
app.yoursite.com CNAME ─▶│ админка       ┘             │      │  (встроенный sshd)│
                         └─────────────────────────────┘      └───────────────────┘
```

Агент сам подключается к серверу по `wss://` (наружу нужен только 443), поэтому NAT и CGNAT не мешают.

## Что умеет

- **`bnat ssh`** — поднимает на агенте встроенный SSH-сервер (shell с pty, exec, scp/sftp, `ssh -L`) и выдаёт `ssh -p <порт> tun.bnat.example.com`. Пускает только ключи, которые добавлены в админке: их можно разрешить на все туннели или на конкретные. Ключи прилетают агентам сразу, перезапускать ничего не надо. Шифрование SSH сквозное, VPS трафик не видит.
- **`bnat ssh --local 127.0.0.1:22`** — вместо встроенного сервера пробрасывает на уже стоящий openssh (тогда пускает его собственный `authorized_keys`).
- **`bnat http 3000`** — `https://<name>.bnat.example.com`, сертификат Let's Encrypt выпускается автоматически. Работают WebSocket и SSE.
- **Свои домены** — в админке привязываете `app.yoursite.com` к HTTP-туннелю, у DNS-провайдера делаете `CNAME app.yoursite.com → bnat.example.com`, жмёте «Check DNS», и сертификат выпускается сам.
- **`bnat tcp 5432`** — любой TCP-сервис на случайном порту.
- **Админка** — онлайн-туннели (трафик, подключения, кнопка disconnect), клиенты с привязкой по одноразовому коду, SSH-ключи, домены, закреплённые имена и порты. У каждого имени фиксированный порт и поддомен, и при переподключении они не меняются.

## Установка сервера

DNS (все записи на IP сервера):

```
A  bnat.example.com      → 1.2.3.4   # админка + точка входа агентов
A  *.bnat.example.com    → 1.2.3.4   # HTTP-туннели
A  tun.bnat.example.com  → 1.2.3.4   # (опционально) красивое имя для ssh/tcp
```

Открыть порты: `80`, `443`, `20000-29999/tcp`.

Бинарники для Linux, macOS и Windows лежат в [Releases](https://github.com/Suro4ek/bnat/releases). Docker-образ: `ghcr.io/suro4ek/bnat` (по умолчанию запускает `bnat server`, для агента — `docker run ghcr.io/suro4ek/bnat http …`). Если есть Go, можно поставить так: `go install github.com/Suro4ek/bnat/cmd/bnat@latest`.

```bash
bnat server --domain bnat.example.com --tcp-host tun.bnat.example.com --data /var/lib/bnat
```

На первом запуске в лог печатается сгенерированный пароль админки (или задайте `--admin-password` / `BNAT_ADMIN_PASSWORD`). Для systemd есть готовый юнит `deploy/bnat-server.service`.

## Docker

Примеры в [`examples/`](examples):

| Пример | Что внутри |
|---|---|
| [`local-demo`](examples/local-demo/docker-compose.yml) | Всё на одной машине без домена и TLS: сервер, тестовое приложение whoami, HTTP- и SSH-агенты. Удобно, чтобы посмотреть, как всё работает. |
| [`server`](examples/server/docker-compose.yml) | Сервер для VPS: `cp .env.example .env`, вписать домен, `docker compose up -d`. |
| [`agent`](examples/agent/docker-compose.yml) | Агент на домашней машине: публикует веб-приложение из того же compose-проекта и SSH самого хоста. |

Быстрый старт демо:

```bash
cd examples/local-demo
docker compose up -d bnat
# http://localhost:8080, пароль demo → Clients → добавить клиента → скопировать код
BNAT_PAIR_CODE=XXXX-XXXX docker compose up -d
curl -H 'Host: whoami.localhost' localhost:8080
```

Агенту в контейнере не нужен интерактивный `bnat login`. Достаточно передать `BNAT_SERVER` и `BNAT_PAIR_CODE`: при первом запуске он сам привяжется и сохранит токен в `/config`. Этот путь стоит смонтировать как volume, тогда при перезапусках код больше не понадобится.

Если перед bnat уже стоит Caddy/nginx с TLS, запускайте `--tls=false --http 127.0.0.1:8080 --public-scheme https` и проксируйте на него `bnat.example.com` и `*.bnat.example.com`, не забыв про WebSocket upgrade.

## Использование агента

1. Админка → **Clients** → создать клиента (например `home-server`). Появится одноразовый код на 15 минут:
   ```bash
   bnat login https://bnat.example.com K7QM-3XPA
   ```
   Агент обменивает код на постоянный ключ, и в админке у клиента появляется `user@host` машины. Повторно код не сработает. Кнопка «New code» перепривязывает клиента к другой машине, старая при этом сразу отключается.
2. Админка → **SSH keys** → вставить свой `~/.ssh/id_ed25519.pub`.
3. На машине за NAT:
   ```bash
   bnat ssh -n home
   #   ssh -p 21028 suro@tun.bnat.example.com
   ```
4. С любого компьютера: `ssh -p 21028 tun.bnat.example.com`.

Ещё примеры:

```bash
bnat http 3000 -n app                      # https://app.bnat.example.com
bnat http 5173 -n vite --host-header rewrite   # для dev-серверов, проверяющих Host
bnat tcp 5432 -n pg                        # tun.bnat.example.com:2xxxx
bnat ssh -n nas --local 192.168.1.10:22    # SSH другой машины в локалке
```

Для постоянной работы есть `deploy/bnat-agent.service` (systemd user unit).

## CI/CD

- **CI** (`.github/workflows/ci.yml`) запускается на каждый push и PR: gofmt, `go mod tidy`, `go vet`, тесты с `-race` на Linux и macOS, кросс-сборка под все платформы, сборка Docker-образа. В тестах есть e2e-сценарий: сервер, привязка по коду, TCP-, HTTP- и SSH-туннели.
- **Release** (`.github/workflows/release.yml`) запускается по тегу:
  ```bash
  git tag v0.1.0 && git push origin v0.1.0
  ```
  Сначала идут тесты, затем GoReleaser собирает бинарники с чек-суммами и публикует GitHub Release, а образ `ghcr.io/suro4ek/bnat:{0.1.0,0.1,latest}` собирается под amd64 и arm64. Теги вида `v0.2.0-rc1` публикуются как pre-release, и `latest` на них не ставится.
- **Deploy** (`.github/workflows/deploy.yml`) после релиза обновляет бинарник на VPS по SSH и перезапускает `bnat-server`. Его можно запустить и вручную из вкладки Actions. Пока не настроен, он просто пропускается. Настройка в Settings → Secrets and variables → Actions:
  - variable `DEPLOY_HOST`: `bnat.example.com`
  - variable `DEPLOY_USER`: по умолчанию `root`; другому пользователю нужен sudo без пароля
  - secret `DEPLOY_SSH_KEY`: приватный ключ для входа на VPS
  - secret `DEPLOY_KNOWN_HOSTS`: вывод `ssh-keyscan bnat.example.com`

## Локальная разработка

```bash
go build -o bin/bnat ./cmd/bnat
bin/bnat server --domain localhost --tls=false --http :8080 --admin-password dev
# админка: http://localhost:8080, туннели: http://<name>.localhost:8080
go test -race ./...
```

## Модель безопасности и ограничения

- Встроенный sshd запускает сессии от пользователя, под которым запущен `bnat`, а логин в `ssh user@…` игнорируется. Нужен вход под разными юзерами — используйте `--local` на системный sshd.
- Любой привязанный клиент может поднимать туннели с любым свободным именем. Это рассчитано на одного владельца или доверенный круг.
- Перебор кодов привязки ограничен: 10 неудачных попыток с одного IP за 10 минут.
- Сертификаты выпускаются только для занятых имён и подтверждённых доменов, поэтому случайные поддомены не съедают лимиты Let's Encrypt (50 сертификатов в неделю на домен). Если HTTP-туннелей много, стоит перейти на wildcard-сертификат через DNS-01.
- Данные хранятся в `data/bnat.json`, сертификаты в `data/certs/`. Токены лежат в виде sha256-хэшей.
