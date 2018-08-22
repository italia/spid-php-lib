FROM php:7.2-apache
RUN a2enmod rewrite
COPY . /app/
RUN rm -rf /var/www/html && ln -s /app/example /var/www/html
RUN chmod -R 777 /app/
RUN echo 'PassEnv SP_FQDN' >> /etc/apache2/conf-enabled/expose-env.conf \
    && echo 'PassEnv SP_NAME' >> /etc/apache2/conf-enabled/expose-env.conf \
    && echo 'PassEnv SP_SCHEMA' >> /etc/apache2/conf-enabled/expose-env.conf \
    && echo 'PassEnv IDP_SCHEMA' >> /etc/apache2/conf-enabled/expose-env.conf \
    && echo 'PassEnv IDP_FQDN' >> /etc/apache2/conf-enabled/expose-env.conf
