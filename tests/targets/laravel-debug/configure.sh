#!/bin/sh
# Turns a fresh Laravel install into the vulnerable test target.
# All secrets below are FAKE fixtures; integration tests assert they never
# appear unredacted in StackHound output.
set -eu
cd /var/www/html

set_env() {
    if grep -q "^$1=" .env; then
        sed -i "s|^$1=.*|$1=$2|" .env
    else
        echo "$1=$2" >> .env
    fi
}

# LRV-01 / LRV-02 / LRV-04: debug on, local env (Telescope's default gate is open in local)
set_env APP_ENV local
set_env APP_DEBUG true
set_env DB_CONNECTION sqlite
set_env DB_DATABASE /var/www/html/database/database.sqlite
set_env DB_PASSWORD shound-fake-db-password
set_env MAIL_PASSWORD shound-fake-mail-password
set_env AWS_ACCESS_KEY_ID AKIASHOUNDFAKEKEY000
set_env AWS_SECRET_ACCESS_KEY shound/fake/secret/access/key/0000000000
cp .env .env.backup

touch database/database.sqlite
php artisan telescope:install
php artisan migrate --force

# LRV-03: a log file with a fake secret in its context
mkdir -p storage/logs
echo '[2026-01-01 00:00:00] local.ERROR: shound fixture log entry {"api_token":"shound-fake-log-token"}' \
    >> storage/logs/laravel.log

# LRV-06: a git repository whose remote URL embeds a fake credential.
# /var/www/html belongs to www-data while the build runs as root.
git config --global --add safe.directory /var/www/html
git init -q
git config user.email fixture@example.test
git config user.name shound-fixture
git add -A
git commit -qm "fixture"
git remote add origin https://deploy:shound-fake-git-token@git.example.test/team/app.git

php artisan config:clear
chown -R www-data:www-data storage bootstrap/cache database
