#!/bin/sh
# managed-by: safehost-billing-public:v1
set -eu
/usr/bin/docker run --rm --network host \
  -v /etc/letsencrypt:/etc/letsencrypt \
  -v /var/lib/letsencrypt:/var/lib/letsencrypt \
  -v /var/log/letsencrypt:/var/log/letsencrypt \
  -v /var/lib/safehost-acme:/var/www/acme \
  certbot/certbot@sha256:c23159d30afdd9c97960578aa4654f5901de6cae394958f894074dedd55e599d \
  renew --non-interactive --cert-name safehost-billing-ip "$@"
/usr/sbin/nginx -t
/usr/bin/systemctl reload nginx
