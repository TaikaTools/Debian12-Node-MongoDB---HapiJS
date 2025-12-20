# ================================================
# Fresh SETUP SCRIPT FOR Web server (Debian 12)
# ================================================
# This script installs:
# - Node.js 24.x LTS
# - MongoDB 8.0 (secure, auth enabled)
# - PM2 (process manager)
# - Nginx (reverse proxy + fast static/uploads)
# - tmux + htop
# - Creates database with prompted name
# - Generates strong random secrets .env 
# - installs HapiJS and miscellaneous
# - Interactive SSL setup, Let's Encrypt, A+ ready
# - Harding security, tweaking performance
# ================================================

usage:

wget https://raw.githubusercontent.com/TaikaTools/Debian12-Node-MongoDB---HapiJS/refs/heads/main/debian12_setup.sh

chmod u+x debian12_setup.sh

./debian12_setup.sh
