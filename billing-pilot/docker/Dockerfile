FROM fossbilling/fossbilling:0.8.8@sha256:304c2572d007166d49be05082ef8eddb4da133534b41bfa911ec1225e02f8d12
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY fossbilling/SafehostProxmox.php /opt/pilot/SafehostProxmox.php
COPY fossbilling/install.php fossbilling/seed.php /opt/pilot/
COPY config.json /opt/pilot/config.json
COPY fossbilling/mod_servicecustom_manage.html.twig /opt/pilot/mod_servicecustom_manage.html.twig
# Servicecustom 0.8.8 requires Plugin/... relative to PHP include_path.
RUN printf 'max_execution_time=950\ninclude_path=".:/var/www/html/library:/usr/local/lib/php"\n' > /usr/local/etc/php/conf.d/zz-pilot.ini
