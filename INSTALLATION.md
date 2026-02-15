# 🚀 FamilyQuest - Przewodnik Instalacji

## 📋 Spis treści
1. [Szybki start (Demo)](#szybki-start-demo)
2. [Instalacja produkcyjna](#instalacja-produkcyjna)
3. [Konfiguracja bazy danych](#konfiguracja-bazy-danych)
4. [Deployment](#deployment)
5. [Troubleshooting](#troubleshooting)

---

## 🎯 Szybki start (Demo)

### Wymagania
- Przeglądarka (Chrome, Firefox, Safari, Edge)
- Prosty serwer HTTP

### Krok 1: Pobierz pliki
```bash
# Sklonuj lub pobierz wszystkie pliki z projektu
git clone https://github.com/yourusername/familyquest.git
cd familyquest
```

### Krok 2: Uruchom serwer
```bash
# Python
python -m http.server 8000

# Lub Node.js
npx http-server -p 8000

# Lub PHP
php -S localhost:8000
```

### Krok 3: Otwórz w przeglądarce
```
http://localhost:8000
```

### Krok 4: Zaloguj się
```
Email: demo.parent@example.com
Hasło: Demo-Change-This-Password
PIN: 1234
```

✅ **Gotowe!** Aplikacja działa w trybie demo z LocalStorage.

---

## 🏗️ Instalacja produkcyjna

### Wymagania systemowe

#### Backend
- **Node.js** >= 18.0.0
- **PostgreSQL** >= 14.0
- **npm** >= 9.0.0

#### Opcjonalne
- **Redis** (cache)
- **NGINX** (reverse proxy)
- **PM2** (process manager)

---

## 📊 Konfiguracja bazy danych

### Krok 1: Zainstaluj PostgreSQL

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### macOS
```bash
brew install postgresql@14
brew services start postgresql@14
```

#### Windows
Pobierz instalator: https://www.postgresql.org/download/windows/

### Krok 2: Utwórz bazę danych

```bash
# Zaloguj się jako postgres
sudo -u postgres psql

# W PostgreSQL shell:
CREATE DATABASE familyquest;
CREATE USER familyquest_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE familyquest TO familyquest_user;
\q
```

### Krok 3: Uruchom migrację

```bash
# Edytuj .env z danymi dostępowymi
cp .env.example .env
nano .env

# Wklej URL bazy:
DATABASE_URL="postgresql://familyquest_user:your_secure_password@localhost:5432/familyquest"

# Uruchom migrację
psql -U familyquest_user -d familyquest -f postgres-schema.sql
```

### Krok 4: Zweryfikuj instalację

```bash
# Sprawdź tabele
psql -U familyquest_user -d familyquest -c "\dt"

# Sprawdź dane demo
psql -U familyquest_user -d familyquest -c "SELECT * FROM families;"
```

---

## 🔧 Setup Backend (Node.js)

### Krok 1: Zainstaluj zależności

```bash
npm install
```

### Krok 2: Skonfiguruj Prisma

```bash
# Wygeneruj Prisma Client
npm run db:generate

# (Opcjonalnie) Uruchom Prisma Studio
npm run db:studio
```

### Krok 3: Utwórz plik backend

**Utwórz: `server.js`**

```javascript
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGINS?.split(',') || '*',
  credentials: true
}));
app.use(express.json());
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API routes (implement based on your needs)
app.use('/api/auth', require('./routes/auth'));
app.use('/api/children', require('./routes/children'));
app.use('/api/tasks', require('./routes/tasks'));
app.use('/api/completions', require('./routes/completions'));
app.use('/api/rewards', require('./routes/rewards'));
app.use('/api/stats', require('./routes/stats'));

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.listen(PORT, () => {
  console.log(`🚀 FamilyQuest API running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
});
```

### Krok 4: Uruchom backend

```bash
# Development
npm run dev

# Production
npm start
```

---

## 🌐 Deployment

### Option 1: Vercel (Frontend)

```bash
# Zainstaluj Vercel CLI
npm i -g vercel

# Deploy
vercel

# Production
vercel --prod
```

### Option 2: Heroku (Full stack)

```bash
# Zainstaluj Heroku CLI
brew install heroku/brew/heroku

# Login
heroku login

# Create app
heroku create familyquest-app

# Add PostgreSQL
heroku addons:create heroku-postgresql:hobby-dev

# Deploy
git push heroku main

# Migracja
heroku run npm run db:migrate
```

### Option 3: Digital Ocean / AWS

#### 1. Utwórz Droplet/EC2
- Ubuntu 22.04 LTS
- Min 1GB RAM
- SSH access

#### 2. Setup serwera

```bash
# SSH do serwera
ssh root@your-server-ip

# Update system
apt update && apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

# Install PostgreSQL
apt install -y postgresql postgresql-contrib

# Install NGINX
apt install -y nginx

# Install PM2
npm install -g pm2
```

#### 3. Deploy aplikacji

```bash
# Sklonuj repo
git clone https://github.com/yourusername/familyquest.git
cd familyquest

# Install dependencies
npm install

# Setup .env
nano .env
# (wklej konfigurację)

# Setup database
sudo -u postgres psql -f postgres-schema.sql

# Start with PM2
pm2 start server.js --name familyquest
pm2 save
pm2 startup
```

#### 4. Konfiguracja NGINX

```bash
nano /etc/nginx/sites-available/familyquest
```

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
# Enable site
ln -s /etc/nginx/sites-available/familyquest /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

#### 5. SSL (Let's Encrypt)

```bash
apt install -y certbot python3-certbot-nginx
certbot --nginx -d yourdomain.com
```

---

## 🔒 Bezpieczeństwo

### Hasła i tokeny

```bash
# Generate secure JWT secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generate bcrypt hash (for default password)
node -e "const bcrypt = require('bcrypt'); bcrypt.hash('Demo-Change-This-Password', 10).then(h => console.log(h))"
```

### Firewall (UFW)

```bash
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw enable
```

### Fail2Ban (Optional)

```bash
apt install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban
```

---

## 🧪 Testing

### Unit tests

```bash
npm test
```

### Integration tests

```bash
npm run test:integration
```

### Load testing

```bash
# Install Artillery
npm install -g artillery

# Run load test
artillery quick --count 10 --num 50 http://localhost:3000/api/health
```

---

## 📊 Monitoring

### PM2 Monitoring

```bash
pm2 monit
pm2 logs familyquest
```

### PostgreSQL Monitoring

```bash
# Connections
psql -U familyquest_user -d familyquest -c "SELECT count(*) FROM pg_stat_activity;"

# Database size
psql -U familyquest_user -d familyquest -c "SELECT pg_size_pretty(pg_database_size('familyquest'));"
```

---

## 🐛 Troubleshooting

### Problem: Port już używany

```bash
# Znajdź proces
lsof -i :3000

# Kill proces
kill -9 PID
```

### Problem: Baza danych connection refused

```bash
# Sprawdź czy PostgreSQL działa
sudo systemctl status postgresql

# Restart
sudo systemctl restart postgresql

# Sprawdź logi
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

### Problem: Permission denied

```bash
# Fix permissions
sudo chown -R $USER:$USER /path/to/familyquest
chmod -R 755 /path/to/familyquest
```

### Problem: Out of memory

```bash
# Zwiększ swap
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Problem: CORS errors

Sprawdź `CORS_ORIGINS` w `.env`:
```
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
```

### Problem: JWT expired

Zwiększ expiration w `.env`:
```
JWT_EXPIRES_IN=30d
```

---

## 🔄 Backup & Restore

### Backup bazy danych

```bash
# Full backup
pg_dump -U familyquest_user familyquest > backup_$(date +%Y%m%d).sql

# Compressed backup
pg_dump -U familyquest_user familyquest | gzip > backup_$(date +%Y%m%d).sql.gz
```

### Restore

```bash
# From SQL file
psql -U familyquest_user familyquest < backup_20240211.sql

# From compressed
gunzip -c backup_20240211.sql.gz | psql -U familyquest_user familyquest
```

### Automated backups (cron)

```bash
crontab -e
```

Add:
```
0 2 * * * pg_dump -U familyquest_user familyquest | gzip > /backups/familyquest_$(date +\%Y\%m\%d).sql.gz
```

---

## 📈 Scaling

### Horizontal scaling

1. **Load balancer** (NGINX)
2. **Multiple app instances** (PM2 cluster)
3. **PostgreSQL read replicas**
4. **Redis cache**

### Vertical scaling

1. **Upgrade Droplet/EC2**
2. **Optimize PostgreSQL** (shared_buffers, work_mem)
3. **Add indexes** (check slow queries)

---

## 📚 Dodatkowe zasoby

- [PostgreSQL docs](https://www.postgresql.org/docs/)
- [Prisma docs](https://www.prisma.io/docs)
- [Express.js docs](https://expressjs.com/)
- [NGINX docs](https://nginx.org/en/docs/)

---

## 🆘 Pomoc

### Community
- GitHub Issues
- Discord Server
- Email: support@familyquest.com

---

**Powodzenia z instalacją! 🎉**
