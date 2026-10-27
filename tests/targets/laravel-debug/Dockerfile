# Deliberately misconfigured Laravel target for StackHound integration tests.
# NEVER expose this container beyond 127.0.0.1: it serves .env, .git and logs.
#
# Misconfiguration modelled: shared-hosting style deployment where the web root is
# the project root (not /public) and a root .htaccess forwards unknown paths to
# public/. Every real file in the project is therefore downloadable.
FROM php:8.3-apache

ARG LARAVEL_CONSTRAINT=^12.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod rewrite \
    && sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV COMPOSER_ALLOW_SUPERUSER=1 \
    COMPOSER_NO_INTERACTION=1

WORKDIR /var/www/html

# Old framework majors may carry advisories; this target must still install.
RUN (composer config --global audit.block-insecure false || true) \
    && composer create-project --prefer-dist "laravel/laravel:${LARAVEL_CONSTRAINT}" . \
    && composer require laravel/telescope

COPY configure.sh /usr/local/bin/configure-target
COPY root.htaccess /var/www/html/.htaccess
RUN sh /usr/local/bin/configure-target
