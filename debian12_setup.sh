#!/bin/bash

# This script installs:
# - Node.js 24.x LTS
# - MongoDB 8.0 (secure, auth enabled)
# - Nginx (reverse proxy + fast static/images)
# - Hapi.js for REST API, auth, logic, and database
# - PM2 (process manager with clustering)
# - ufw (Uncomplicated Firewall)
# - Optional: tmux for session persistence
# - Creates a dedicated non-root system user for the app
# - Generates strong random secrets and SFTP password
# - Interactive SSL setup (Let's Encrypt real or test cert)
# - Optional self-signed cert for IP access
# - Hardening security and performance tweaks

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
read -p "1/4 - Domain (e.g., mydomain.com, without www.), blank for no domain []: " DOMAIN
DOMAIN=${DOMAIN:-yourdomain_dot_com}

if [ "$DOMAIN" != "yourdomain_dot_com" ]; then
  read -p "2/4 - CertBot: fake or real (type real) []" CERT
else
  echo "2/4 - No Domain, skipping"
fi
CERT=${CERT:-fake}
echo "cert is: $CERT"

read -p "3/4 - RestAPI (Hapi) Port [3003]: " PORT
PORT=${PORT:-3003}

read -p "4/4 - Database, Folder and User name [ntt]: " NAME
NAME=${NAME:-ntt}

# 2. Add User
if ! id "$NAME" &>/dev/null; then
    sudo adduser --system --group --no-create-home --disabled-password "$NAME"
    sudo usermod -s /bin/bash "$NAME"

    # Generate a strong 32-char password (letters, digits, symbols)
    GEN_PASS=$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9!@#$%^&*()' | head -c32)

    # Set it for the user (non-interactive)
    echo "$NAME:$GEN_PASS" | sudo chpasswd

    # Optional: Show it (for logging or user)
    echo "Generated password for user: $NAME: $GEN_PASS"
fi

# 3. System update
sudo apt update && sudo apt upgrade -y
sudo apt install -y gnupg

# 4. MongoDB
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
sudo apt-get update -y
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

sudo systemctl start mongod

# 5. Tools
sudo apt install -y ufw nginx
if [ "$DOMAIN" != "yourdomain_dot_com" ]; then
  sudo apt install -y ca-certificates certbot python3-certbot-nginx tmux
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
sudo chown root:root /var/www
sudo chown -R "$NAME:$NAME" $APP_DIR
#sudo chown -R www-data:www-data $APP_DIR
sudo chmod 755 $APP_DIR
cd $APP_DIR

IMAGES_DIR="/srv/images"
sudo mkdir -p $IMAGES_DIR
sudo chown -R www-data:www-data $IMAGES_DIR
sudo chmod 755 $IMAGES_DIR

sudo mkdir -p $APP_DIR/public
sudo chown -R www-data:www-data $APP_DIR/public
sudo chmod 755 $APP_DIR/public

sudo mkdir -p $APP_DIR/logs
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
    
    location /images/ {
        alias $IMAGES_DIR/;
        expires 27d;
        add_header Access-Control-Allow-Origin "*" always;
        add_header Cache-Control "public";
        access_log off;
    }

    location /api/ {
        rewrite ^/api/(.*) /\$1 break;
        proxy_pass http://127.0.0.1:$PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cookie_path / /api/;
        proxy_buffering off;
        
        # proxy_redirect off;
        # proxy_intercept_errors on;
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
    sudo certbot --nginx --test-cert -d "$DOMAIN" -d "www.$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --no-eff-email \
        -m "admin@$DOMAIN"
  fi
    sudo sed -i '/listen 443/a    add_header Strict-Transport-Security "max-age=62772772; includeSubDomains; preload" always;' /etc/nginx/sites-available/$NAME
    sudo sed -i "/listen 443/a    ssl_session_cache shared:SSL:11M;" /etc/nginx/sites-available/$NAME
else
  if [[ $PUBLIC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
          -keyout /etc/ssl/private/$NAME-selfsigned.key \
          -out /etc/ssl/certs/$NAME-selfsigned.crt \
          -subj "/CN=$PUBLIC_IP" \
          -addext "subjectAltName = IP:$PUBLIC_IP,DNS:localhost,IP:127.0.0.1"

      sudo sed -i \
        -e 's/listen 80;/listen 443 ssl;/' \
        -e 's/listen \[::\]:80;/listen \[::\]:443 ssl;/' \
        -e "/server_name _;/a\    ssl_certificate /etc/ssl/certs/$NAME-selfsigned.crt;\n    ssl_certificate_key /etc/ssl/private/$NAME-selfsigned.key;" \
        /etc/nginx/sites-available/$NAME

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

# 15. Format and mount XFS volumes (if present)
if [ -b /dev/sdb ] || [ -b /dev/sdc ]; then
  # MongoDB data on /dev/sdb
  if [ -b /dev/sdb ]; then
      echo "Setting up XFS for MongoDB on /dev/sdb..."
      sudo mkfs.xfs -f /dev/sdb
      sudo mkdir -p /mongodb-data
      sudo mount /dev/sdb /mongodb-data
      UUID_MONGO=$(sudo blkid -s UUID -o value /dev/sdb)
      echo "UUID=$UUID_MONGO /mongodb-data xfs defaults,noatime 0 2" | sudo tee -a /etc/fstab
      sudo rsync -av /var/lib/mongodb/ /mongodb-data/   # Copy existing data if any
      sudo systemctl stop mongod
      sudo mv /var/lib/mongodb /var/lib/mongodb.bak   # Backup
      sudo ln -s /mongodb-data /var/lib/mongodb       # Symlink or update dbPath in conf
      sudo chown -R mongodb:mongodb /mongodb-data
  fi

  # Images on /dev/sdc
  if [ -b /dev/sdc ]; then
      echo "Setting up XFS for images on /dev/sdc..."
      sudo mkfs.xfs -f /dev/sdc
      sudo mount /dev/sdc /srv/images
      UUID_IMAGES=$(sudo blkid -s UUID -o value /dev/sdc)
      echo "UUID=$UUID_IMAGES /srv/images xfs defaults,noatime 0 2" | sudo tee -a /etc/fstab
      sudo chown -R www-data:www-data /srv/images
      sudo chmod 755 /srv/images
  fi

  # Mount all (in case of reboot in script)
  sudo mount -a

  # Restart MongoDB
  sudo systemctl start mongod
fi

sudo chown -R "$NAME:$NAME" $APP_DIR
#sudo chown -R www-data:www-data $APP_DIR
sudo chmod 755 $APP_DIR
sudo systemctl restart ssh
cd $APP_DIR

# 16. Final
echo "=============================================================="
echo "COMPLETE! Secrets (COPY IF NEEDED):"
echo " "
echo "MongoDB Admin: $ADMIN_PASS"
echo "MongoDB App:   $APP_PASS"
echo "JWT Secret:    $JWT_SECRET"
echo " "
echo "WWW Folder:    $APP_DIR"
echo "Image Folder:  $IMAGES_DIR"
echo "username:      $NAME"
echo "SFTP password: $GEN_PASS"
if [ "$DOMAIN" != "yourdomain_dot_com" ]; then
echo "SSL email:     admin@$DOMAIN  (Certbot $CERT)"
fi
echo " "
echo "add server.js + pm2.js"
echo "=============================================================="
