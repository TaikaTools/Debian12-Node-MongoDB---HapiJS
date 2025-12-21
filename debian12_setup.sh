#!/bin/bash

# ===================================================
# SETUP Debian 12 - Node.js + Hapi + MongoDB + Nginx 
# ===================================================
# This script installs:
# - Node.js 24.x LTS
# - MongoDB 8.0 (secure, auth enabled)
# - PM2 (process manager)
# - Nginx (reverse proxy + fast static/uploads)
# - ufw + curl + (optional: tmux + htop)
# - Creates a dedicated non-root system user for the app
# - Creates database with prompted name
# - Generates strong random secrets .env
# - installs HapiJS and miscellaneous
# - Interactive SSL setup (Let's Encrypt, A+ ready)
# - Hardening security, tweaking performance

set -e  # Exit on error

# 1. Prompts with defaults
read -p "1/6 - Domain (e.g., mydomain.com, without www.): " DOMAIN
DOMAIN=${DOMAIN:-yourdomain.com}

read -p "2/6 - Database name [ntt]: " DATABASE
DATABASE=${DATABASE:-ntt}

read -p "3/6 - Folder [ntt]: " FOLDER
FOLDER=${FOLDER:-ntt}

read -p "4/6 - RestAPI Port [3003]: " PORT
PORT=${PORT:-3003}

read -p "5/6 - System user name [ntt]: " USER_NAME
USER_NAME=${USER_NAME:-ntt}
if ! id "$USER_NAME" &>/dev/null; then
    sudo adduser --system --group --no-create-home --disabled-password "$USER_NAME"
    echo "Created system user: $USER_NAME"
fi

read -n 1 -r -s -p "6/6 - Install Tmux and hTop [y]: " INSTALL_EXTRA
INSTALL_EXTRA=${INSTALL_EXTRA:-y}

# 2. System update & tools
sudo apt update && sudo apt upgrade -y
sudo apt install -y ca-certificates curl gnupg ufw nginx certbot python3-certbot-nginx
if [[ $INSTALL_EXTRA == "Y" || $INSTALL_EXTRA == "y" ]]; then
  sudo apt install -y htop tmux
fi

# 3. Node.js + PM2
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs
npm install pm2 -g
pm2 update

# 4. MongoDB
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
sudo apt update
sudo apt install -y mongodb-org

# 5. Hardening (always apply)
sudo mkdir -p /var/lib/mongodb /var/log/mongodb
sudo chown -R mongodb:mongodb /var/lib/mongodb /var/log/mongodb
sudo sed -i 's/bindIp: .*/bindIp: 127.0.0.1/' /etc/mongod.conf

# Higher ulimits + disable THP
sudo bash -c 'cat > /etc/security/limits.d/mongodb.conf <<EOF
mongodb soft nofile 64000
mongodb hard nofile 64000
mongodb soft nproc 64000
mongodb hard nproc 64000
EOF'
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/defrag

# 6. Secrets & Users – idempotent
if ! grep -q "^  authorization: enabled" /etc/mongod.conf; then
  echo "First run: Generating secrets and creating users..."

  ADMIN_PASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64)
  APP_PASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64)
  JWT_SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 128)

  # Enable auth
  sudo sed -i '/#security:/a\security:\n  authorization: enabled' /etc/mongod.conf

  # Create admin without auth
  sudo systemctl start mongod
  echo "Waiting 11 seconds for MongoDB to initialize..."
  sleep 11

  mongosh admin <<EOF
db.createUser({ user: "admin", pwd: "$ADMIN_PASS", roles: [ { role: "root", db: "admin" } ] })
exit
EOF
  sudo systemctl restart mongod
  echo "Waiting 11 seconds (again) for MongoDB to initialize (again)..."
  sleep 11

  # Create app user
  mongosh -u admin -p "$ADMIN_PASS" --authenticationDatabase admin <<EOF
use $DATABASE
db.createUser({ user: "app", pwd: "$APP_PASS", roles: [ "readWrite" ] })
exit
EOF
else
  echo "Auth already enabled - skipping user creation."
fi

# 7. Project setup
APP_DIR="/var/www/$FOLDER"
UPLOADS_DIR="/srv/images/$FOLDER"
sudo mkdir -p $APP_DIR
sudo chown -R "$USER_NAME:$USER_NAME" $APP_DIR
sudo chmod 755 $APP_DIR
cd $APP_DIR

sudo mkdir -p $UPLOADS_DIR
sudo chown -R "$USER_NAME:$USER_NAME" $UPLOADS_DIR
sudo chmod 755 $UPLOADS_DIR

sudo mkdir -p /var/www/$FOLDER/public
sudo chown www-data:www-data /var/www/$FOLDER/public
sudo chmod 755 /var/www/$FOLDER/public

# Save secrets to .env (only if not already present)
cat > .env <<EOF
PORT=$PORT
MONGODB_URI="mongodb://app:$APP_PASS@127.0.0.1:27017/$DATABASE?authSource=$DATABASE"
JWT_SECRET=$JWT_SECRET
ADMIN_PASS=$ADMIN_PASS
APP_PASS=$APP_PASS
DOMAIN=https://$DOMAIN
NODE_ENV=production
UPLOADS_PATH=$UPLOADS_DIR
NODEMAILER_HOST=smtp.gmail.com
NODEMAILER_PORT=465
NODEMAILER_USER=yourgmail@gmail.com
NODEMAILER_PASS=yourapppassword
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
EOF
chmod 600 .env
sudo chown "$USER_NAME:$USER_NAME" "$APP_DIR/.env"

npm init -y > /dev/null 2>&1
npm install @hapi/hapi @hapi/boom @hapi/joi @hapi/jwt @hapi/cookie @hapi/inert mongoose bcryptjs dotenv stripe nodemailer uuid > /dev/null 2>&1

# 10. Nginx config
sudo bash -c "cat > /etc/nginx/sites-available/$FOLDER <<'EOF'
server {
    listen 80;
    server_name _;

    location /uploads/ {
        alias $UPLOADS_DIR/;
        expires 30d;
        add_header Cache-Control \"public\";
        access_log off;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location / {
        root /var/www/$FOLDER/public;
        try_files $uri $uri/ /index.html;
        expires 1h;
        add_header Cache-Control "public";
    }

    location ~ /\.env { deny all; }
    location ~ /\.git { deny all; }
}
EOF"

sudo ln -sf /etc/nginx/sites-available/$FOLDER /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx
sudo systemctl enable nginx

# 9. Firewall
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable

# 10. SSL
if [ "$DOMAIN" != "yourdomain.com" ]; then
  sudo sed -i "s/server_name _;/server_name $DOMAIN www.$DOMAIN;/" /etc/nginx/sites-available/$FOLDER
  sudo nginx -t && sudo systemctl reload nginx
  sudo certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN"
  # A+ snippet...
  sudo bash -c 'cat > /etc/nginx/snippets/ssl-params.conf <<EOF
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10M;
ssl_session_tickets off;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
EOF'
  sudo sed -i '/listen 443/a include /etc/nginx/snippets/ssl-params.conf;' /etc/nginx/sites-available/$FOLDER
  sudo openssl dhparam -dsaparam -out /etc/nginx/dhparam.pem 4096
  echo "ssl_dhparam /etc/nginx/dhparam.pem;" | sudo tee -a /etc/nginx/snippets/ssl-params.conf
  sudo nginx -t && sudo systemctl reload nginx
fi

# 11. Cleanup
sudo apt purge -y cups* exim4* postfix* vim vim-tiny net-tools bluetooth modemmanager avahi-daemon telnet ftp nis ypbind rpcbind x11-common 2>/dev/null || true
sudo apt autoremove -y
sudo apt autoclean
sudo systemctl disable --now cups bluetooth avahi-daemon 2>/dev/null || true

# 12. Final
echo "=============================================================="
echo "COMPLETE! Secrets (COPY IF NEEDED):"
echo "Admin: $ADMIN_PASS"
echo "App: $APP_PASS"
echo "JWT: $JWT_SECRET"

if [ "$DOMAIN" != "yourdomain.com" ]; then
echo "ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;"
echo "ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;"
fi
echo "cd $APP_DIR && add server.js + ecosystem.config.js"
echo "=============================================================="
