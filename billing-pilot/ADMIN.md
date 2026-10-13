# Административный портал FOSSBilling

Safe-host backend обращается к `POST /admin-portal.php` с отдельным Bearer
`ADMIN_PORTAL_BRIDGE_TOKEN`. Owner token не подходит. Авторизация выполняется до
bootstrap FOSSBilling; браузеру оба токена не передаются. Nginx допускает этот
endpoint только с IP основного backend. Ответы имеют `Cache-Control: no-store`.

`./billing prepare` создаёт `.secrets/admin-portal-token` и соответствующую запись
в приватном `.env`, сохраняя существующие DB/owner secrets. Значение должно
совпадать в FOSS и основном backend, быть длиной не менее 32 символов и отличаться
от owner token. Секреты не помещают в argv, URL, Git или логи.

## Контракт

Каждый запрос содержит доверенный `actor: {account: UUID, email: string}`,
полученный backend из административной сессии. Endpoint принимает только:

- `sync_clients`: `clients: [{account, name, email, registeredAt}]`, максимум 200.
  Все timestamp в UTC ISO. UUID mapping в `data/portal/portal.sqlite` является
  авторитетным. Повторный sync обновляет контакт и имя, сохраняя регистрацию.
  Native email остаётся `portal-UUID@safe-host.ru`, last_name — UUID; реальные
  email и имя сохраняются в billing_email/first_name. Полное имя хранится в
  profile SQLite; native first_name ограничено 100 символами. Синтаксически
  проверенный Spring email сохраняется без дополнительной зависимости от DNS.
  Для legacy account `email: null` разрешён: profile хранит пустой контакт,
  native billing_email не перезаписывается. Dashboard возвращает известный native
  billing_email или пустую строку («—» в UI), не синтетический email как контакт.
- `dashboard`: `dayStart`, `dayEnd` — UTC ISO границы московского дня, вычисленные
  основным backend. CamelCase ответ включает source FOSSBilling, stats, clients,
  servers, hosts, events. Clients включает регистрации без VPS. `plans` позволяет
  группировку. BalanceMinor/currency — нативный баланс FOSSBilling, **отдельный
  от prepaid кошелька основного сайта**. Endpoint не пополняет оба кошелька.
- `action`: `operationId: UUID`, `orderId: int`, `command`, `reason`, actor.
  Commands: start, stop, block, unblock, archive, restore, purge. Reason обязателен
  для всех команд, 3–500 символов. Для purge обязателен `confirmVmid: int`, точно
  совпадающий с управляемым VMID. Возвращает сохранённую operation со state pending.
- `operation`: `operationId`, actor. Возвращает `{id, orderId, action, state,
  error}`; state pending/running/done/failed. Изменение payload для того же ID даёт
  HTTP 409; точное повторение возвращает сохранённый результат.

Audit хранит UUID/email оператора, reason и operation ID. `events.actor` в
dashboard — строка email. Ошибки наружу и в audit безопасные; raw exceptions,
api_token, начальные пароли и хэши в dashboard/status не попадают. Метрики guest
filesystem неизвестны без исправного guest agent и тогда равны null. Legacy
orphan без исходного времени создания имеет `createdAt: null` (UI показывает «—»).

HTTP: 400 неверный контракт, 401 неверный token, 404 неизвестная operation/order,
409 конфликт identity, 413 слишком большой JSON, 503 временная недоступность.
Максимальный JSON — 128 KiB. Привилегированные методы находятся в EngineGateway,
AdminBridge и PortalBridge; Client `servicecustom_call` их не получает.

## Обработка и восстановление

`ansible/update.yml` обновляет root engine, endpoint и image, затем запускает
отдельный compose `admin-worker` (профиль admin). Для ручного запуска после
установки endpoint и настроенного restricted SSH transport:

```sh
docker compose -p safehost-billing up -d --build admin-worker
docker compose -p safehost-billing logs --tail 50 admin-worker
```

Worker читает сохранённую SQLite очередь каждые 3 секунды. Повтор после временной
ошибки — через 30 секунд. Один worker выполняет mutation; блокировки сериализуют
owner/admin writers, чтения не ждут mutation. Транзакция DB не охватывает SSH/PVE
или native FOSS side effects. Root engine сохраняет immutable operation receipt
перед эффектом и повторяет тот же VM/order после потерянного ответа. После restart
worker восстанавливает pending/running. Постоянная ошибка VMID/state/capacity даёт
failed; после исправления причины нужна новая operation ID.
Ошибка выполнения `qm`/`pvesh` остаётся retryable, включая persisted restoring или
archiving: root receipt не становится failed, worker повторяет тот же operation
ID после устранения внешнего сбоя, не создавая новый order/VM.

Stop использует graceful shutdown с 30-секундным ожиданием и явным force fallback.
Обычный owner stop имеет публичную фазу suspended, native FOSS order остаётся
active. Admin dashboard показывает stopped. Native suspend/unsuspend — block/
unblock; owner не снимает block и не запускает archived/cancelled/deleted VPS.
Внутреннее native suspended отделено от explicit admin blocked: обычный FOSS
unsuspend снимает только native suspension и не снимает admin block. Повторный
native suspend сохраняет уже установленный admin block. Его снимает только
audited admin operation unblock, после чего обновляется native FOSS status.

Archive хранит диск, credential и слот без срока, отключает onboot и снимает
RAM/CPU reservation. Restore доступен только admin, проверяет RAM с host reserve
и всеми unmanaged VM (включая существующие 100/101/102), не создаёт новый VPS.
При restore учитывается фактически настроенная RAM целевой VM, даже если её
изменили напрямую в Proxmox; target исключается из суммы и добавляется один раз.
Purge проверяет marker/node/network/volumes перед снятием protection, удаляет
только управляемую VM с её проверенными дисками, очищает snippet/credential и
освобождает слот. Tombstone retired_allocation и retired_orders сохраняют историю
и запрещают старому order воздействовать на новый VPS с повторно использованным
VMID. Account quota освобождается только после подтверждённого deleted.

Native FOSS cancel/delete сохраняет диск. При native order_delete owner видит
cancelled и не восстанавливает VPS. Admin может archive, restore или purge такого
orphan через тот же audit/marker contract; новый FOSS order не создаётся. Даже после
admin restore owner остаётся cancelled. Пропавшая либо чужая VM даёт missing с
reason, не deleted; слот автоматически не освобождается и VM не клонируется.

Перед deployment/rollback сохраняют MariaDB, `data/portal/portal.sqlite`, root
allocations SQLite, credential.key и config.sha256; старые backup не накатывают
поверх новых allocation/tombstone. Code-only rollback требует остановки admin
worker и сохранения DB/history. Миграция существующих services этим artifact не
выполняется. Проверка `./billing test` использует новый изолированный Docker
project и FakePVE, не производственный Proxmox.
