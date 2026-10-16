> Сеть обновлена 16 октября 2026: текущий [FOSSBilling](https://45.9.88.50/). Старые адреса ниже относятся к предыдущему развёртыванию. Актуальные параметры и ограничения — [PUBLIC-IPV4.md](PUBLIC-IPV4.md).

# Кабинет → FOSSBilling → Proxmox

`POST /portal.php` — закрытый серверный контракт. Доступ: HTTPS, IP сервера кабинета `157.228.152.183`, `Authorization: Bearer <PORTAL_BRIDGE_TOKEN>`. Токен хранится в `.secrets/portal-token` и `.env`, не в Git и не в браузере. `./billing prepare` создаёт его, сохраняя существующие пароли. При обновлении установленной системы нужен исходный `.env` и исходные SSH-ключи.

Тело: `{"action":"create","account":"<UUID аккаунта>","reference":"<UUID checkout>","plan":"mini"}`. Тарифы: `mini`, `small`, `medium`. ОС Ubuntu 24.04; общий публичный IP, отдельный SSH-порт. `create` выдаёт бесплатный заказ ценой 0 без счёта и запускает его через штатный обработчик FOSSBilling. Настоящих платежей в этом режиме нет. Повтор использует тот же заказ; иной reference для того же account отклоняется. Изменять тариф повторного запроса запрещено.

Действия: `create`, `status`, `password`, `stop`, `start`. В `status`/`create` пароль отсутствует. Пароль возвращает только `password` у активной VM после завершения cloud-init и проверки SSH. Остановка приостанавливает заказ, запуск возобновляет. Автоматическая переустановка, удаление диска и перезапуск не включены.

Связи UUID → клиент → заказ сохраняются в `/var/www/html/data/portal/portal.sqlite` внутри постоянного Docker volume. Сначала записывается резерв и order_id, потом выполняется активация. После потери ответа заказ восстанавливается по стабильному названию и владельцу. У клиента FOSSBilling служебный email `portal-<UUID>@safe-host.ru`; вход и настоящий контакт остаются в Spring. Исходящие письма отключены.

Резервная копия: согласованный dump MariaDB, `data/portal`, `/var/lib/safehost-billing/allocations.sqlite`, `/var/lib/safehost-billing/credential.key`, конфигурация пула и секреты. Копировать SQLite через backup API; открытый WAL нельзя копировать отдельно. Слоты отменённых заказов и диски сохраняются.

Обновление: исходный `./billing prepare`, затем `./billing update`. `ansible/update.yml` обновляет engine, приложение и endpoint; nginx-конфигурация `public/nginx.conf` ограничивает endpoint IP сервера кабинета. Секрет `PORTAL_BRIDGE_TOKEN` передаётся backend как `SAFEHOST_BILLING_TOKEN`; URL — `https://80.249.131.4/portal.php`. Проверка `./billing test` использует отдельный Docker-проект, настоящий FOSSBilling и симулятор Proxmox.

## Смена пароля и задержки

При первом SSH-входе `Password` и `Current password` требуют один и тот же временный пароль. Новый вводят на `New password`, повторяют на `Retype new password`. В терминале ввод не отображается. Ошибка PAM на Current password не меняет пароль. При необходимости используйте `ssh -tt` для интерактивной смены.

Запрос password проверяет владельца, активную VM, cloud-init и SSH в одном обращении к адаптеру. Фоновые status/readiness и выдача пароля используют shared locks; изменение VM остаётся exclusive. Если идёт создание или изменение VM, чтение отказывает сразу для повторного запроса, вместо длительного ожидания за provisioning. Выдача не меняет пароль и не создаёт VM.
