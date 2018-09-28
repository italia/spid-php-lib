FROM php:7.2-apache
RUN a2enmod rewrite
RUN service apache2 restart
VOLUME /app
RUN chmod -R 777 /app/
RUN rm -rf /var/www/html && ln -s /app/examples/docker /var/www/html
