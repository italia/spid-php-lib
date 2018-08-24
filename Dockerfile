FROM php:7.2-apache
RUN a2enmod rewrite
COPY . /app/
RUN rm -rf /var/www/html && ln -s /app/example /var/www/html
RUN chmod -R 777 /app/
