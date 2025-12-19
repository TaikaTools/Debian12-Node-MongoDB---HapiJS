#!/bin/bash

# ==================================================
# SETUP SCRIPT FOR Web (Debian 12, December 19, 2025)
# ==================================================
# This script installs:
# - Node.js 24.x LTS
# - MongoDB 8.0 (secure, auth enabled)
# - PM2 (process manager)
# - Nginx (reverse proxy + fast static/uploads)
# - tmux + htop
# - Creates database with prompted name
# - Generates strong random secrets .env 
# - installs HapiJS and deps
# - Interactive SSL setup (Let's Encrypt, A+ ready)
# - Harding security, tweak performance
# ==================================================

read -p " 1/3 - Domain (e.g., mydomain.com, without www.): " DOMAIN
read -p " 2/3 - Database (e.g., MyDatabase for database name): " DATABASE
read -p " 3/3 - Folder (e.g., for myfolder folder): " FOLDER

set -e  # Exit on any error

# 1. System update & tools
sudo apt update && sudo apt upgrade -y
sudo apt install -y ca-certificates curl gnupg ufw vim htop tmux net-tools nginx certbot python3-certbot-nginx

# 2. Node.js 24.x LTS + PM2
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs
npm install pm2 -g
pm2 update

# 3. MongoDB 8.0
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
sudo apt update
sudo apt install -y mongodb-org

# 4. MongoDB hardening
sudo mkdir -p /var/lib/mongodb /var/log/mongodb
sudo chown -R mongodb:mongodb /var/lib/mongodb /var/log/mongodb
sudo sed -i 's/bindIp: .*/bindIp: 127.0.0.1/' /etc/mongod.conf
sudo sed -i '/#security:/a\security:\n  authorization: enabled' /etc/mongod.conf

# Higher ulimits + disable THP
sudo bash -c 'cat > /etc/security/limits.d/mongodb.conf <<EOF
mongodb soft nofile 64000
mongodb hard nofile 64000
mongodb soft nproc 64000
mongodb hard nproc 64000
EOF'
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/defrag

# 5. Start MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# 6. Generate secrets
ADMIN_PASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64)
APP_PASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64)
JWT_SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 128)

# 7. Create users + DB
mongosh admin <<EOF
db.createUser({ user: "admin", pwd: "$ADMIN_PASS", roles: [ { role: "root", db: "admin" } ] })
exit
EOF
sudo systemctl restart mongod
mongosh -u admin -p "$ADMIN_PASS" --authenticationDatabase admin <<EOF
use $DATABASE
db.createUser({ user: "app", pwd: "$APP_PASS", roles: [ "readWrite" ] })
exit
EOF

# 8. Project + uploads + .env + deps
APP_DIR=~/$FOLDER
UPLOADS_DIR=/var/www/$FOLDER/uploads
sudo mkdir -p $UPLOADS_DIR
sudo chown $USER:$USER $UPLOADS_DIR
mkdir -p $APP_DIR
cd $APP_DIR

cat > .env <<EOF
PORT=3000
MONGO_URI=mongodb://app:$APP_PASS@127.0.0.1:27017/$DATABASE?authSource=$DATABASE
JWT_SECRET=$JWT_SECRET
NODE_ENV=production
UPLOADS_PATH=$UPLOADS_DIR

NODEMAILER_HOST=smtp.gmail.com
NODEMAILER_PORT=465
NODEMAILER_USER=yourgmail@gmail.com
NODEMAILER_PASS=yourapppassword

STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_SUCCESS_URL=https://$DOMAIN/stripe_success
STRIPE_CANCEL_URL=https://$DOMAIN/stripe_cancel
STRIPE_RETURN_URL=https://$DOMAIN/stripe_return
EOF
chmod 600 .env

npm init -y > /dev/null 2>&1
npm install @hapi/hapi @hapi/boom @hapi/joi @hapi/jwt @hapi/cookie @hapi/inert mongoose bcryptjs dotenv stripe nodemailer uuid > /dev/null 2>&1

# 9. Nginx config
sudo bash -c 'cat > /etc/nginx/sites-available/$FOLDER <<EOF
server {
    listen 80;
    server_name _;

    location /uploads/ {
        alias $UPLOADS_DIR/;
        expires 30d;
        add_header Cache-Control "public";
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location ~ /\.env { deny all; }
}
EOF'

sudo ln -sf /etc/nginx/sites-available/$FOLDER /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx
sudo systemctl enable nginx

# 10. Firewall
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable

# 11. SSL setup (interactive)
echo "=================================================="
echo "SSL TIME - Enter domain for both domain.com & www.domain.com"
if [ -n "$DOMAIN" ]; then
  sudo sed -i "s/server_name _;/server_name $DOMAIN www.$DOMAIN;/" /etc/nginx/sites-available/$FOLDER
  sudo nginx -t && sudo systemctl reload nginx
  sudo certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN"
  # A+ snippet
  sudo bash -c 'cat > /etc/nginx/snippets/ssl-params.conf <<EOF
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10M;
ssl_session_tickets off;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
EOF'
  sudo sed -i '/listen 443/a include /etc/nginx/snippets/ssl-params.conf;' /etc/nginx/sites-available/$FOLDER
  echo "Generating DH params (10-20 min)..."
  sudo openssl dhparam -dsaparam -out /etc/nginx/dhparam.pem 4096
  echo "ssl_dhparam /etc/nginx/dhparam.pem;" | sudo tee -a /etc/nginx/snippets/ssl-params.conf
  sudo nginx -t && sudo systemctl reload nginx
fi

# 12. Cleanup unnecessary packages/services
sudo apt purge -y cups* exim4* postfix* bluetooth modemmanager avahi-daemon telnet ftp nis ypbind rpcbind x11-common 2>/dev/null || true
sudo apt autoremove -y
sudo apt autoclean

# 13. Disable any leftover services
sudo systemctl disable --now cups bluetooth avahi-daemon 2>/dev/null || true

# 14. Final
echo "=================================================="
echo "COMPLETE! Secrets (COPY NOW):"
echo "Admin: $ADMIN_PASS"
echo "App:   $APP_PASS"
echo "JWT:   $JWT_SECRET"
echo "cd $APP_DIR && add server.js + ecosystem.config.js + pm2 start"
echo "=================================================="

echo "Cleanup complete - server leaner and more secure!"
