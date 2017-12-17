FROM php:7.1-cli
ENV DEBIAN_FRONTEND noninteractive
ENV COMPOSER_ALLOW_SUPERUSER 1

RUN apt-get update -q \
 && apt-get install unzip git libssl-dev libmcrypt-dev -y \
 && docker-php-ext-install mcrypt

WORKDIR /root

RUN curl -sS https://getcomposer.org/installer | php \
  && mv composer.phar /usr/local/bin/composer

COPY . /code

WORKDIR /code

RUN composer install --prefer-dist --no-interaction

CMD php ./vendor/bin/phpunit
