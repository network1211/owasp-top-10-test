#!/usr/bin/env bash
set -euo pipefail

# ---- Config ----
APP_NAME="owasp-app"
APP_USER="${SUDO_USER:-$USER}"     # run as the invoking user
APP_DIR="$PWD"                     # project dir = current dir
VENV_DIR="$APP_DIR/.venv"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

echo "[1/6] Installing system packages..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip openssl

echo "[2/6] Creating virtualenv and installing Python deps..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install \
  flask \
  pyjwt \
  flask-swagger-ui \
  jwcrypto \
  gunicorn

echo "[3/6] Ensuring keys exist (private.pem / public.pem)..."
if [[ ! -f "$APP_DIR/private.pem" ]]; then
  openssl genrsa -out "$APP_DIR/private.pem" 2048
fi
if [[ ! -f "$APP_DIR/public.pem" ]]; then
  openssl rsa -in "$APP_DIR/private.pem" -pubout -out "$APP_DIR/public.pem"
fi
chmod 600 "$APP_DIR/private.pem" || true

echo "[4/6] Checking Swagger file..."
if [[ ! -f "$APP_DIR/static/swagger.json" ]]; then
  echo "ERROR: $APP_DIR/static/swagger.json not found. Create it before continuing."
  exit 1
fi

echo "[5/6] Creating systemd service at $SERVICE_FILE ..."
sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=OWASP API Vulnerabilities Demo (Flask via gunicorn)
After=network.target

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$VENV_DIR/bin/gunicorn -b 0.0.0.0:5003 owasp-test-app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo "[6/6] Enabling and starting service..."
sudo systemctl daemon-reload
sudo systemctl enable --now "$APP_NAME"

echo "Done!"
echo
echo "Status:"
sudo systemctl status "$APP_NAME" --no-pager || true
echo
echo "Quick test (from another shell):"
echo "  curl -s http://127.0.0.1:5003/swagger | head"
