# Debian 12 Production Setup for Node.js + HapiJS + MongoDB + Nginx

A fully automated, idempotent setup script for a secure, high-performance web server on **Debian 12 (Bookworm)**.

### Features
- Node.js 24.x LTS (current Active LTS)
- MongoDB 8.0 Community Edition (authentication enabled, localhost-bound)
- PM2 (production process manager with clustering)
- Nginx (reverse proxy, fast static file serving for uploads/images)
- Creates a dedicated non-root system user for the app
- Optional: tmux (session persistence)
- Interactive prompts for:
  - Domain name
  - Database name
  - Project folder
  - App port
- Auto-generates strong random secrets (saved to `.env`)
- Installs HapiJS + common dependencies (mongoose, stripe, nodemailer, etc.)
- Interactive Let's Encrypt SSL setup (A/A+ rated)
- Security hardening and performance tweaks (ulimits, THP disabled, unnecessary services removed)

Perfect for deploying secure HapiJS apps with image uploads, Stripe payments, authentication, and email.

### Requirements
- Fresh Debian 12 installation
- Root/sudo access
- (For SSL) Domain name with DNS A record pointing to server IP

### Usage

```bash
wget https://raw.githubusercontent.com/TaikaTools/Debian12-Node-MongoDB---HapiJS/refs/heads/main/debian12_setup.sh
chmod +x debian12_setup.sh
./debian12_setup.sh
rm debian12_setup.sh
