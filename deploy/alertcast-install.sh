#!/usr/bin/env bash
# Встановлення alertcast (Linux із systemd) з розпакованого релізу: sudo ./alertcast-install.sh
# Повторний запуск оновлює програму й не чіпає налаштувань, токенів і БД.
# Після успішного встановлення пакет (ця тека, архів і SHA256SUMS поруч) видаляється;
# --keep — залишити.
set -euo pipefail
cd "$(dirname "$0")"
PKG=$(pwd -P)
DOCS=https://github.com/Hyrol7/ukrainealarm-alertcast/blob/main/docs

KEEP=0
[[ ${1:-} == --keep ]] && KEEP=1

[[ $EUID -eq 0 ]] || { echo "Запустіть через sudo"; exit 1; }
command -v systemctl >/dev/null || { echo "Потрібен systemd (systemctl не знайдено)"; exit 1; }

case "$(uname -m)" in
  x86_64)  BIN=alertcast-linux-amd64 ;;
  aarch64) BIN=alertcast-linux-arm64 ;;
  *) echo "Непідтримувана архітектура: $(uname -m)"; exit 1 ;;
esac

id alertcast &>/dev/null || useradd --system --no-create-home --home-dir /var/lib/alertcast --shell /usr/sbin/nologin alertcast

install -m 0755 "$BIN" /usr/local/bin/alertcast.new
mv -f /usr/local/bin/alertcast.new /usr/local/bin/alertcast
install -m 0755 alertcast-update.sh /usr/local/sbin/alertcast-update
install -m 0644 alertcast.service /etc/systemd/system/alertcast.service
install -d -m 0700 -o root -g root /etc/alertcast

ENV=/etc/alertcast/alertcast.env
NEW=0
if [[ ! -f $ENV ]]; then
  install -m 0600 -o root -g root alertcast.env.example "$ENV"
  NEW=1
  echo "Створено $ENV."
fi

systemctl daemon-reload
systemctl enable alertcast >/dev/null

if [[ $NEW -eq 0 ]]; then
  systemctl restart alertcast
  sleep 2
  systemctl --no-pager --lines=8 status alertcast || true
else
  echo
  echo "Далі:"
  echo "  1. Налаштування:  sudo nano $ENV   (PUBLIC_URL, за потреби VPN_LISTEN)"
  echo "  2. Reverse proxy: публічний сайт → $(grep -E '^PUBLIC_LISTEN=' "$ENV" | cut -d= -f2), адмінка (лише VPN) → $(grep -E '^ADMIN_LISTEN=' "$ENV" | cut -d= -f2): $DOCS/proxy.md"
  echo "  3. Запуск:        sudo systemctl start alertcast"
  echo "  4. Адмінка:       sudo alertcast admin setup   (пароль і 2FA)"
  echo "  5. Перевірка:     sudo alertcast check"
  echo "  6. Перший токен:  в адмінці або sudo alertcast token add --name \"Мій телефон\""
fi
VERSION=$(/usr/local/bin/alertcast version)
echo
echo "alertcast $VERSION встановлено. Оновлення: sudo alertcast-update"

# Прибирання: лише якщо це справді розпакований реліз (а не, скажімо, тека з кодом).
if [[ $KEEP -eq 0 && $(basename "$PKG") == alertcast && -f $PKG/alertcast-linux-amd64 && ! -e $PKG/.git && $PKG != / ]]; then
  PARENT=$(dirname "$PKG")
  cd /
  rm -rf -- "$PKG"
  rm -f -- "$PARENT/alertcast-$VERSION.tar.gz"
  if [[ -f $PARENT/SHA256SUMS ]] && grep -q "alertcast-$VERSION\.tar\.gz" "$PARENT/SHA256SUMS"; then
    rm -f -- "$PARENT/SHA256SUMS"
  fi
  echo "Файли встановлення видалено ($PKG). Перейдіть в іншу теку: cd ~"
fi
