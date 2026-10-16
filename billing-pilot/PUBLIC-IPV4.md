# Публичный IPv4: выдача и эксплуатация

Код выдаёт отдельный IPv4 новой VM через сайт → FOSSBilling → root engine. Обычный NAT остаётся прежним режимом. Подсеть Selectel подключена, хост и действующие NAT endpoints перенесены. Canary завершена, клиентская выдача включена 16 октября 2026 за 450 ₽/мес.

## Включение после canary

Runtime-код engine — `a3d4953`, SHA-256 `8d46a537f89e18f20772c7d382c2b1543213de2dff498d18bf71f2e584f63c71`. Production config и его seal согласованы; `public_network.enabled:true` синхронизирован с source config и metadata FOSSBilling. Код сайта сохраняет временные базовые тарифы 10/20/30 ₽: mini с IPv4 — 460 ₽/мес. Стоимость подсети по API Selectel — 3 120 ₽/мес.; клиентских адресов 10, доплата 450 ₽ утверждена владельцем.

Две отдельные тестовые VM прошли выдачу пароля и обязательную смену при первом SSH-входе, HTTP80, HTTPS443, DNS/egress с выделенного IP, изоляцию хоста/приватной сети и блокировку подмены IP. Archive освободил адрес, другая VM получила его повторно, restore вернул первой VM новый адрес, перезагрузка сохранила lease и прямой SSH. После штатного purge обеих QA VM все 10 адресов свободны; QA invoices и payment attempts сайта — 0. Все 6 прежних allocation/config/PID сохранены; отдельный NAT-заказ, появившийся параллельно, также сохранён.

Canary выявила и закрыла ошибки ожидания guest agent, порядка carrier/boot, передачи QGA payload и чтения ownership marker при boot guard reload. Network capacity теперь читает конфиги через штатные `load_current_config(id,0)` QEMU/LXC одним Perl-процессом: сохраняется pending-effective поведение API. Старый и новый наборы занятых адресов на production совпали; чтение сократилось с 11,09 до 0,59 с, полный `/api/capabilities` — 0,85 с. Все 83 Python-теста прошли, включая выполнение Perl-адаптера и отказ при ошибке чтения. Независимое ревью кода, operator scripts и maintainability/style завершено без открытых замечаний.

Установку совместимого read adapter выполнили атомарно под shared operation lock, исключающим изменения VM, и отдельным exclusive code-update lock. Работающие readers продолжили со старым модулем; API/worker для этой правки не останавливались. Реальная оплата нового заказа не отправлялась: на сайте проверены наличие IPv4 и неоплаченный draft 460 ₽; синтетический аккаунт удалён.

Резервные копии canary/engine/allocator остаются на Proxmox в `/root/safehost-ipv4-canary-20261016/`, FOSS DB — в одноимённом root-каталоге VM101. Сайт: `/etc/safehost/ipv4-enabled-20261016/` содержит прежний env, PostgreSQL dump и подтверждение включения. Клиентские базы и секреты локально не выгружались.

## Выделенная подсеть: проверено 16 октября 2026

Письмо владельца сверено с API Selectel `GET /servers/v2/network` и `GET /servers/v2/network/ipam/subnet`. Пул SPB-4, VLAN **1348**, сеть `9a94e415-da7d-5cbb-a5a0-faf2ecf5539e`, подсеть `7c0653ad-b891-5f3c-a034-b7e343691168`.

| Назначение | Адрес |
| --- | --- |
| Подсеть / маска | `45.9.88.48/28` / `255.255.255.240` |
| Шлюз | `45.9.88.49` |
| Адрес Proxmox | `45.9.88.50` |
| Клиентский пул | `45.9.88.51`–`45.9.88.60`, 10 адресов |
| VRRP, исключены из выдачи | `45.9.88.61`, `45.9.88.62` |
| Broadcast, исключён автоматически | `45.9.88.63` |

`networks/selectel-spb4-45.9.88.48-28.json` — **patch полного конфигурационного файла**, не готовая замена установленного config. Он резервирует первый доступный адрес хосту и сохраняет `enabled:false`. Объединить только `public_ip` и `public_network` с проверенной копией установленного config; остальные параметры и секреты не заменять. VLAN переключается на порту Selectel, не добавляется как guest VLAN tag.

Proxmox использует `45.9.88.50/28`, gateway `45.9.88.49` на `vmbr0`; `vmbr1` остаётся `10.10.10.1/24`. Проверены постоянный interfaces через `ifquery --check`, DNS и default route. Старый адрес и временная source policy route удалены после проверки нового доступа.

## Первоначальная выкладка 16 октября

Код `36bed9c7ecb1c2d361e4331b8c50bc6836aecb4b` включён в `main` и установлен: root engine, сетевые модули, FOSSBilling bridge/plugin и отдельный admin worker. Engine SHA-256: `2baeb4d4763e01104e52a0ff21a12638615814a1318e2ba408cbcefbb2a170ad`. Исходный production engine совпал с предком `d8aae1c9168f2ecf3b11c0900081825c99b0ad99`.

Backup allocator/adapter и FOSSBilling/portal SQLite остаются на соответствующих серверах в `/root/safehost-release-backup-20261016/`; целостность SQLite проверена. После обновления 6 прежних allocation rows, spec/phase и VM inventory совпали с backup; установленный config и seal не менялись. Новые отдельные admin/finance tokens связаны с backend сайта; прежний клиентский token сохранён. Административный HTTPS endpoint ограничен IP сайта; проверены чтение dashboard, отказ клиентскому token и финансовый callback без создания операции.

Профиль применён к sealed config штатным `network_migrate.py`. Интернет-порт `8ad31852-6cf6-556c-8f39-b5b5a99afd47` переведён с VLAN 114 на **1348**. Новый FOSSBilling URL — `https://45.9.88.50/`; доверенный IP-сертификат выпущен, staging dry-run продления прошёл. Оба backend URL сайта обновлены, отдельные tokens сохранены. Все 6 allocation rows, конфиги и PID VM совпали с backup; снаружи проверены SSH22/2222/2223 и 22220–22225. Status worker сайта сам обновил 4 его Proxmox endpoints. На этом промежуточном этапе пул оставался выключенным; итог включения после canary описан выше.

## Выполненный переход без KVM

API консоли возвращал `500 C00001 BadRequest / Internal error`. По запросу владельца использован независимый автоматический откат:

1. Новый `.50` зарегистрирован в IPAM Selectel; прежний общий IP остался закреплён за сервером. Старый адрес/default в Linux сохранены; добавлены вторичный `.50/28` и отдельная source policy route через `.49`.
2. На сервере сайта запущен watchdog с API Selectel: без подтверждения он возвращает конкретный Internet-порт в прежнюю сеть и запускает backend. Токен передан через stdin и хранится только в памяти процесса. Выбор commit/rollback атомарный и неизменяемый; учитываются `is_processing`, `is_apply`, `is_enabled` порта. Таймер — 300 секунд, проверка нового доступа — до 180 секунд.
3. Первая проверка не подтвердила исходящий доступ из-за зависимости DNS от прежнего default. Watchdog фактически вернул VLAN 114; прежний SSH и backend восстановились. После исправления probe использует известный IP сайта, сохраняя TLS CA/SNI/Host.
4. Повторная попытка подтвердила SSH по прежним trusted host keys и исходящий HTTPS с `.50`. Только после acknowledgment `committed` закреплены новый default/interfaces, hostname mapping и управляемый NAT. Сохранены все зарезервированные порты 2223 и 22220–22229; перезапусков VM не было. Затем перенесены FOSS URL/TLS и backend URLs сайта.
5. Удалены временные старый IP, policy rule/table и только прежние web NAT-правила VM101. Проверка interfaces совпала с runtime; правил с прежним IP не осталось. `safehost-public-networks.service` активен и предшествует `pve-guests.service`.

Watchdog прошёл 8 unit tests и независимое ревью; race commit/rollback исправлен до использования. Резервные копии перехода: Proxmox `/root/safehost-network-cutover-20261016/`, дополнительный sealed backup — `/var/lib/safehost-billing/backups/network-1eb2892441f6407eb6724f82bd28db3a/`. Журнал первого отката на сайте — `/etc/safehost/network-cutover-20261016-attempt1/`; подтверждение второго — `/etc/safehost/network-cutover-20261016/`. Клиентские базы и секретные env локально не выгружались.

## Что хранится где

- Сайт: аккаунт, исходный checkout, подтверждённая оплата, immutable цена и UUID резерва. ЮKassa остаётся платёжным провайдером сайта.
- FOSSBilling: привязка account/reference → native order и очередь административных операций. Native order имеет нулевую цену, чтобы FOSSBilling не списывал оплату второй раз; его баланс остаётся отдельным учётом.
- `/var/lib/safehost-billing/allocations.sqlite`: единственный allocator IPv4 и поколений владения. Не редактировать таблицы вручную.
- Proxmox: два NIC публичной VM; приватный канал для SSH readiness и отдельный публичный NIC. Один default route, через публичный gateway.
- Host nftables: отдельная bridge table `safehost_<VMID>`. Она ограничивает IP/MAC/ARP, VLAN, IPv6, обращения к хосту и приватным сервисам. Новые VM используют `firewall=0` на этих NIC, поскольку фильтрацию выполняют эти таблицы; глобальный Proxmox firewall не переключается.

## Заказ и оплата

1. Клиент выбирает IPv4 в форме новой VM. Наличие и цена поступают с сервера.
2. Сайт сохраняет платёжное намерение, резервирует IP через FOSSBilling и подтверждает `network_payment_pending` до обращения к платёжному провайдеру.
3. До отправки платежа неоплаченный hold истекает через 15 минут. После начала оплаты/при неизвестном исходе адрес не освобождается по таймеру.
4. Только проверенная успешная оплата создаёт VM. Повтор использует тот же checkout, FOSS order и lease; второй VM/IP/платёж не создаётся.
5. Клиент видит IP, SSH22, пользователя `vpsadmin` и прежнюю выдачу временного пароля. Для готовности проверяются cloud-init, приватный SSH и SSH по выделенному IP.
6. Подтверждённый отказ/отмена оплаты освобождает ещё не назначенный hold после сверки. Оплаченная ошибка provisioning остаётся видимой и повторяется без нового списания.

## Жизненный цикл

| Действие | Адрес | Деньги и диск |
| --- | --- | --- |
| Stop / block / billing suspend | Сохраняется | Прежние правила расхода; диск сохраняется |
| Archive | Stop → запрет onboot → удаление публичного NIC → deny guards → release | Диск бессрочно; расход остатка заморожен, автоплатежи выключены |
| Restore | Новый hold → NIC disconnected → guards нового lease → carrier up → boot/guest agent → netplan update → SSH readiness | Расход возобновляется после подтверждённого запуска; автоплатежи выключены |
| Cancel / native delete | Освобождается только после остановки и изоляции | Диск сохраняется; услуга финансово завершается |
| Purge | После подтверждённого destroy | Удаляются диски/реквизиты; сохраняется история денег/владения |
| Missing / неизвестный эффект | Удерживается до сверки | Автоматической выдачи адреса другому заказу нет |

Слот VM и IP независимы: архив сохраняет слот/диск, но возвращает IPv4 в пул. Восстановление может изменить IP; клиенту нужно обновить свои DNS и allowlists. Старый адрес и SSH не отображаются как доступ к архивной VM. При неудачном restore engine останавливает и изолирует VM; если изоляцию подтвердить не удалось, IP не освобождается.

## Подготовка реальной сети Selectel

Стандартная выделенная подсеть требует публичного VLAN того же пула SPB-4 и смены адреса хоста. Одновременное использование текущего общего `80.249.131.4` и выделенного адреса не поддерживается. Адрес SPB-5 использовать здесь нельзя. Основание: https://docs.selectel.ru/dedicated/networks/public-networks-and-subnets/ .

До любых изменений получить CIDR, gateway, VLAN, допустимые/служебные IP, стоимость и подтверждение числа MAC на порту. Посчитать адрес хоста и служебные адреса отдельно от клиентских. Рекомендация для постоянного URL биллинга — `billing.safe-host.ru`; DNS-запись ещё не считается созданной.

Подготовить **полную копию** установленного engine config, добавив реальные параметры:

```json
{
  "public_ip": "<НОВЫЙ_IP_ХОСТА>",
  "public_network": {
    "enabled": false,
    "pool_id": "selectel-spb4",
    "cidr": "<РЕАЛЬНАЯ_ПОДСЕТЬ/CIDR>",
    "gateway": "<ШЛЮЗ_SELECTEL>",
    "bridge": "vmbr0",
    "host_ip": "<НОВЫЙ_IP_ХОСТА>",
    "reserved": ["<ДОПОЛНИТЕЛЬНЫЕ_СЛУЖЕБНЫЕ_IP>"]
  }
}
```

Это фрагмент, не готовый config. Остальные ключи, включая `template_marker`, node, storage, private IP/bridge, slots, планы и VMID, сохранить точно. Не использовать примерные или чужие адреса. `reserved` может быть пустым; gateway, host IP, network и broadcast исключаются allocator автоматически. Разрешён один пул /16–/30; его изменение требует отдельной миграции, история не перенумеровывается.

Для production использовать прежние deploy/transport keys, known_hosts и секреты установленного биллинга. Секреты, созданные `billing test` в новом worktree, относятся только к локальным тестам; ими нельзя заменять production-конфигурацию.

## Окно перехода и команды

1. Согласовать стоимость и окно. Проверить KVM/Rescue либо подготовить независимый откат обеих сторон сети по описанному выше протоколу. Закрыть создание заказов/оплат, остановить workers и дождаться завершения текущих операций. Сохранить проверенные SSH host keys, конфиги uplink/VM, `iptables-save`, nft tables, `/usr/local/lib/safehost-billing`, SQLite через backup API, `credential.key` и FOSS DB/portal state. Backup только в root-каталоге 0700, файлы 0600.
2. Через резервную консоль либо двухэтапный переход с независимым rollback изменить адрес/маску/gateway и VLAN интернет-порта согласно параметрам Selectel. Сам Ansible не меняет VLAN и не покупает подсеть. Проверить новый management SSH и маршрут в интернет до окончательной фиксации.
3. Привязать **ранее проверенные** SSH host keys к новому адресу хоста и `[NEW_IP]:2223` в project known_hosts. Не отключать StrictHostKeyChecking и не доверять результату одного ssh-keyscan. Обновить конфиг/inventory Proxmox и указать реальный новый адрес.
4. Из корня репозитория подготовить guards и sealed config, сначала с `enabled:false`:

   ```sh
   ./billing-pilot/billing network-prepare --candidate /absolute/path/engine-candidate.json --network-ready
   ```

   Команда проверяет, что новый IP уже назначен хосту, валидирует config/владение VM на копии DB, делает backup, сохраняет журнал миграции, переносит config и digest, переприменяет управляемый NAT с прежними портами и ставит nft boot prerequisite. Старые слоты, диски, пароли и финансовые записи не меняются. Локальный `billing-pilot/config.json` обновляется только после успеха Ansible. Установленный engine сам создаёт новые таблицы.
5. Проверить управляемые NAT-цепочки, которые переприменила команда подготовки, и их загрузку. Сохранить SSH-порты существующих NAT VM и VM101. Не выполнять flush ruleset/iptables или перезапуск всех гостевых VM. Проверить доступ к каждой прежней NAT VM по новому адресу хоста.
6. При использовании hostname создать/проверить DNS отдельно, затем:

   ```sh
   BILLING_PUBLIC_HOST=billing.safe-host.ru ./billing-pilot/billing publish
   ```

   Для числового адреса переменную можно опустить. Обновляются FOSS URL, nginx, ACME и автоматическое продление. Проверить dry-run renew, HTTP redirect, TLS, admin login и доступность server-only endpoint с сервера сайта. `public/check.py` использует тот же `BILLING_PUBLIC_HOST`; запускать только с разрешённым доступом и существующими локальными секретами.
7. На сайте обновить `SAFEHOST_BILLING_URL` и `SAFEHOST_ADMIN_BILLING_URL` на новый FOSS hostname; действующие отдельные токены сохранить. Финансовый callback продолжает указывать на `safe-host.ru`. Дождаться обновления NAT endpoints фоновым status worker и проверить клиентский ЛК.
8. Проверить bridge MAC count, отсутствие foreign IP-конфликтов и host firewall forwarding. `safehost-public-networks.service` должен быть active. Он восстанавливает правила из canonical DB **до** `pve-guests.service`; не перезапускает VM. Снять полный read-only inventory перед canary.
9. В candidate включить `public_network.enabled:true`, повторить `network-prepare`. Выдать одну отдельную тестовую public VM через FOSSBilling, проверить внешний SSH22/HTTP80/HTTPS443, исходящий IP, DNS, guest/host isolation. Затем archive → reuse адреса другой test VM → restore → reboot. Не использовать клиентские данные для destructive QA.
10. Только после успешной canary задать на сайте `SAFEHOST_PUBLIC_IPV4_MONTHLY_PRICE=<СОГЛАСОВАННАЯ_ЦЕНА>` и `SAFEHOST_PUBLIC_IPV4_ENABLED=true`, перезапустить backend и вернуть workers. Цена 160 ₽ из прежнего интерфейса не заменяет расчёт себестоимости. Проверить один реальный новый заказ, immutable чек и тариф.

Пока нет реальной подсети и canary, пункт 10 не выполнять. Переход меняет общий SSH endpoint прежних NAT VM; адреса/порты ЛК обновляет существующий status worker через исходные FOSS bindings. Миграции/конфиги не должны «чиниться» ручной заменой digest.

## Сбой и откат

- Сначала выключить новые public заказы на сайте. Это не удаляет действующие IP/VM и не освобождает pending payment holds.
- При незавершённой sealed migration повторить **тот же candidate**. `network-migration.pending.json` различает old/new config/digest и позволяет продолжить после разрыва между записями. Другой candidate отклоняется.
- Не откатывать DB dump поверх новых заказов/денег/leases. Возврат на backend/engine, не понимающий public NIC и архивные адреса, при действующих public VM запрещён. Оставить совместимую версию, закрыть выдачу и сверить операции.
- Если нужен возврат физической сети, вернуть и ОС-конфиг, и VLAN порта через KVM либо заранее проверенный независимый rollback; проверить management, NAT, FOSS URL/TLS и endpoints сайта. После окончательного перехода старый watchdog повторно не запускать: он не откатывает sealed config, NAT и TLS. Общий IP не считать доступным без свежей проверки его назначения и возможности возврата у Selectel.
- Не снимать guard/boot dependency при подключённых public VM. Сначала остановить/изолировать их и подтвердить lease state; иначе появляется доступ с уже освобождённого адреса.
- При foreign/missing VM, изменённом netplan, недоступном guest agent или неизвестном эффекте смотреть очередь/журнал FOSSBilling и read-only monitor engine. Не освобождать адрес по отсутствию ping. Restore можно повторить прежней операцией после устранения причины; оплата не повторяется.

## Проверки разработчика

```sh
./billing-pilot/billing test
# Дополнительно: реальное ядро Linux, отдельный network namespace контейнера:
docker build -t safehost-public-network-tests -f billing-pilot/tests/Dockerfile.network billing-pilot/tests
docker run --rm --network none --cap-add NET_ADMIN \
  -v "$PWD/billing-pilot/backend:/backend:ro" -v "$PWD/billing-pilot/tests:/tests:ro" \
  safehost-public-network-tests python /tests/linux_public_network.py
```

Первый набор проверяет Python allocator/engine/migration, Ansible syntax и настоящий FOSSBilling 0.8.8 с FakePVE. Второй отправляет реальные Ethernet/IP/ARP/TCP/VLAN пакеты в изолированную Linux bridge: spoofing, host/private access, IPv6, адрес после reuse, host readiness и released deny. Они не заменяют canary у Selectel.
