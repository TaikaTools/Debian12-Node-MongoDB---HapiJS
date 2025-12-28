#!/bin/bash

# ===================================================
# SETUP Debian 12 - Node.js + Hapi + MongoDB + Nginx 
# ===================================================
# This script installs:
# - Node.js 24.x LTS
# - MongoDB 8.0 (secure, auth enabled)
# - Nginx (reverse proxy + fast static/images)
# - Hapi.js for RestAPI, Auth, logic and database
# - PM2 (process manager)
# - ufw FireUncomplicated Firewall + (optional: tmux)
# - Creates a dedicated non-root system user for the app
# - Generates strong random secrets .env
# - Interactive SSL setup (Let's Encrypt, A+ ready)
# - Hardening security, tweaking performance

set -e  # Exit on error

get_public_ip() {
    local ip
    ip=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null)
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"
        return
    fi
    for url in "https://ipinfo.io/ip" "https://ifconfig.me" "https://api.ipify.org" "https://checkip.amazonaws.com"; do
        ip=$(curl -s --max-time 5 "$url")
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return
        fi
    done
    echo "Failed to get public IP" >&2
    return 1
}

PUBLIC_IP=$(get_public_ip)
echo "Server public IP: $PUBLIC_IP"

# 1. Prompts with defaults
read -p "1/5 - Domain (e.g., mydomain.com, without www.), blank for no domain []: " DOMAIN
DOMAIN=${DOMAIN:-yourdomain_dot_com}

if [ "$DOMAIN" != "yourdomain_dot_com" ]; then
  read -p "2/5 - CertBot: fake or real (type real) []" CERT
else
  echo "No Domain, skipping 2/5"
fi
CERT=${CERT:-fake}

read -p "3/5 - Database, Folder and User name [ntt]: " NAME
NAME=${NAME:-ntt}

read -p "4/5 - RestAPI (Hapi) Port [3003]: " PORT
PORT=${PORT:-3003}

read -n 1 -r -s -p "5/5 - Install Tmux [y]: " EXTRA_TOOLS
EXTRA_TOOLS=${EXTRA_TOOLS:-y}

# 2. System update
sudo apt update && sudo apt upgrade -y
sudo apt install -y gnupg

# 3. MongoDB
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
sudo apt-get update -y
sudo apt install -y mongodb-org

# 4. Hardening (always apply)
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

sudo systemctl start mongod

# 4. Add User
NAME=${NAME:-ntt}
if ! id "$NAME" &>/dev/null; then
    sudo adduser --system --group --no-create-home --disabled-password "$NAME"
    echo "Created system user: $NAME"
fi

# 5. Tools
sudo apt install -y ufw nginx
if [ "$DOMAIN" != "yourdomain_dot_com" ]; then
  sudo apt install -y ca-certificates certbot python3-certbot-nginx
fi
if [[ $EXTRA_TOOLS == "Y" || $EXTRA_TOOLS == "y" ]]; then
  sudo apt install -y tmux
fi

# 6. Node.js + PM2
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs
npm install pm2 -g
pm2 update

# 7. Secrets & MongoDB Admin – idempotent
DIDCREATEADMIN=${DIDCREATEADMIN:-n}
if ! grep -q "^  authorization: enabled" /etc/mongod.conf; then
  echo "First run: Generating secrets and creating users..."
  DIDCREATEADMIN=${DIDCREATEADMIN:-y}

  ADMIN_PASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64)
  APP_PASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64)
  JWT_SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 128)

  # Enable auth
  sudo sed -i '/#security:/a\security:\n  authorization: enabled' /etc/mongod.conf

  # Create admin without auth
  mongosh admin <<EOF
db.createUser({ user: "admin", pwd: "$ADMIN_PASS", roles: [ { role: "root", db: "admin" } ] })
exit
EOF
  sudo systemctl restart mongod
else
  echo "Auth already enabled - skipping user creation."
fi

# 8. Project setup
APP_DIR="/var/www/$NAME"
sudo mkdir -p $APP_DIR
sudo chown -R "$NAME:$NAME" $APP_DIR
sudo chown -R www-data:www-data $APP_DIR
sudo chmod 755 $APP_DIR
cd $APP_DIR

IMAGES_DIR="/srv/images"
sudo mkdir -p $IMAGES_DIR
sudo chown -R "$NAME:$NAME" $IMAGES_DIR
sudo chown -R www-data:www-data $IMAGES_DIR
sudo chmod 755 $IMAGES_DIR

sudo mkdir -p $APP_DIR/public
##sudo chown -R "$NAME:$NAME" $APP_DIR/public
sudo chown www-data:www-data $APP_DIR/public
sudo chmod 755 $APP_DIR/public

sudo mkdir -p $APP_DIR/logs
##sudo chown -R "$NAME:$NAME" $APP_DIRlogs
sudo chown www-data:www-data $APP_DIR/logs
sudo chmod 755 $APP_DIR/logs

# 9. Save secrets to .env (only if not already present)
cat > .env <<EOF
DOMAIN=$DOMAIN
HOST=127.0.0.1
PORT=$PORT
UPLOADS_PATH=$IMAGES_DIR
NAMEUSERFOLDER=$NAME
MONGODB_APP="mongodb://app:$APP_PASS@127.0.0.1:27017/$NAME?authSource=$NAME"
# MONGODB_ADMIN="mongodb://admin:$ADMIN_PASS@127.0.0.1:27017/$NAME?authSource=$NAME"
JWT_SECRET=$JWT_SECRET
NODE_ENV=production
# NODEMAILER_HOST=smtp.gmail.com
# NODEMAILER_PORT=465
# NODEMAILER_USER=yourgmail@gmail.com
# NODEMAILER_PASS=yourapppassword
# STRIPE_SECRET_KEY=sk_test_...
# STRIPE_WEBHOOK_SECRET=whsec_...
EOF
chmod 600 .env
sudo chown "$NAME:$NAME" "$APP_DIR/.env"

npm init -y > /dev/null 2>&1
npm install @hapi/hapi @hapi/boom @hapi/joi @hapi/jwt @hapi/cookie @hapi/inert mongoose bcryptjs dotenv stripe nodemailer uuid > /dev/null 2>&1

# 10. Nginx config
sudo bash -c "cat > /etc/nginx/sites-available/$NAME <<'EOF'
server {
    listen 80;
    listen [::]:80;

    server_name _;
    
    #!INJECT!SELF!SIGNED!CERT!#

    location /images/ {
        alias $IMAGES_DIR/;
        expires 27d;
        add_header Cache-Control "public";
        access_log off;
    }

    location /api/ {
        rewrite ^/api/(.*) /\$1 break;
        proxy_pass http://127.0.0.1:$PORT;
        proxy_http_version 1.1;
        # proxy_set_header Upgrade \$http_upgrade;
        # proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        # proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cookie_path / /api/;
        proxy_buffering off;
        
        # proxy_cookie_domain localhost \$host; #Optional: If backend sets a domain, rewrite it (rare for localhost)
        # proxy_redirect off;
        # proxy_set_header X-Forwarded-For \$remote_addr;
        # proxy_set_header X-Forwarded-Proto https;
        # proxy_intercept_errors on;
        # add_header X-Cache-Status \$upstream_cache_status;        
        # proxy_ssl_verify off; #Required for SSL passthrough
    }

    root /var/www/$NAME/public;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
        ## expires 1h;
        ## add_header Cache-Control "public";
    }

    location ~ /\.env { deny all; }
}

EOF"

sudo ln -sf /etc/nginx/sites-available/$NAME /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-available/default
sudo rm -f /etc/nginx/sites-enabled/default
sudo mv /var/www/html/index.nginx-debian.html /var/www/$NAME/public/index.html
sudo rm -rf /var/www/html

sudo nginx -t && sudo systemctl restart nginx
sudo systemctl enable nginx

# 11. Firewall
sudo ufw disable
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw deny in on wlan0
sudo ufw deny out on wlan0

sudo ufw --force enable

# 12. SSL
if [ "$DOMAIN" != "yourdomain_dot_com" ]; then
  sudo sed -i "s/server_name _;/server_name $DOMAIN www.$DOMAIN;/" /etc/nginx/sites-available/$NAME
  sudo nginx -t && sudo systemctl reload nginx
  if [ "$CERT" == "real" ]; then
    sudo certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --no-eff-email \
        -m "admin@$DOMAIN"
  else
    sudo certbot --nginx --test-cert \
        -d "$DOMAIN" -d "www.$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --no-eff-email \
        -m "admin@$DOMAIN"
  fi
    # A+ snippet...
    sudo bash -c 'cat > /etc/nginx/snippets/ssl-params.conf <<EOF
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:10M;
  ssl_session_tickets off;
  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  EOF'
  
  sudo sed -i '/listen 443/a\n    include /etc/nginx/snippets/ssl-params.conf; #A+ snippet (not CertBot)' /etc/nginx/sites-available/$NAME
  sudo openssl dhparam -dsaparam -out /etc/nginx/dhparam.pem 4096
  echo "ssl_dhparam /etc/nginx/dhparam.pem;" | sudo tee -a /etc/nginx/snippets/ssl-params.conf
else
  if [[ $PUBLIC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
          -keyout /etc/ssl/private/$NAME-selfsigned.key \
          -out /etc/ssl/certs/$NAME-selfsigned.crt \
          -subj "/CN=$PUBLIC_IP" \
          -addext "subjectAltName = IP:$PUBLIC_IP,DNS:localhost,IP:127.0.0.1"

      sudo sed -i "s/listen 80;/listen 443 ssl;/" /etc/nginx/sites-available/$NAME
      sudo sed -i "s/listen [::]:80;/listen [::]:443 ssl;/" /etc/nginx/sites-available/$NAME      
      #sudo sed -i "s|#!INJECT!SELF!SIGNED!CERT!#|ssl_certificate /etc/ssl/certs/$NAME-selfsigned.crt;\n    ssl_certificate_key /etc/ssl/private/$NAME-selfsigned.key;|" /etc/nginx/sites-available/$NAME
      sudo sed -i "/server_name _;/a\n    ssl_certificate /etc/ssl/certs/$NAME-selfsigned.crt;\n    ssl_certificate_key /etc/ssl/private/$NAME-selfsigned.key;" /etc/nginx/sites-available/$NAME
      sudo bash -c "cat >> /etc/nginx/sites-available/$NAME <<'EOF'
server {
    listen 80;
    listen [::]:80;

    server_name _;

    return 301 https://\$host\$request_uri;
}
EOF"

  else
      echo "Could not determine public IP — skipping self-signed cert"
  fi
fi

sudo nginx -t && sudo systemctl reload nginx

# 13. Cleanup
sudo apt purge -y cups* exim4* postfix* vim vim-tiny net-tools bluetooth modemmanager avahi-daemon telnet ftp nis ypbind rpcbind x11-common 2>/dev/null || true
sudo apt autoremove -y
sudo apt autoclean
sudo systemctl disable --now cups bluetooth avahi-daemon 2>/dev/null || true

# 14. Create MongoDB app user
if [ "$DIDCREATEADMIN" != "y" ]; then
  mongosh -u admin -p "$ADMIN_PASS" --authenticationDatabase admin <<EOF
use $NAME
db.createUser({ user: "app", pwd: "$APP_PASS", roles: [ "readWrite" ] })
exit
EOF
fi

# 15. Final
echo "=============================================================="
echo "COMPLETE! Secrets (COPY IF NEEDED):"
echo "MongoDB Admin: $ADMIN_PASS"
echo "MongoDB App:   $APP_PASS"
echo "JWT Secret:    $JWT_SECRET"

echo "WWW Folder:    $APP_DIR"
echo "Image Folder:  $IMAGES_DIR"
if [ "$DOMAIN" != "yourdomain_dot_com" ]; then
echo "SSL email:     admin@$DOMAIN"
fi
echo "add server.js + pm2.js"
echo "=============================================================="

cd $APP_DIR
ls
