# Служебные VM

Реестр `/var/lib/safehost-billing/infrastructure.json` задаёт логического владельца
и запрещает операции над перечисленными VMID. Это root state, отдельный от
`/etc/safehost-billing/config.json` и `config.sha256`. Файл должен быть обычным
файлом root:root с режимом `0600`, каталог state — root:root `0700`. Отсутствие
файла означает пустой реестр; повреждённый, небезопасный или неверный по схеме
реестр отклоняет запрос целиком.

Схема версии 1:

```json
{
  "version": 1,
  "servers": [
    {
      "vmid": 101,
      "node": "pve1",
      "account": "9ac2de9e-e907-42f1-b28d-e65a2c1552a8",
      "name": "safehost — биллинг",
      "os": "Ubuntu 24.04",
      "address": "10.10.10.11",
      "publicIpv4": false,
      "configSha256": "<SHA-256 актуальной конфигурации Proxmox>"
    }
  ]
}
```

Для VM 1101 добавляют такую же запись с публичным адресом `45.9.88.54` и
`publicIpv4: true`. `configSha256` обязателен: `engine.fingerprint(config)` от
актуальной конфигурации с удалённым только API-полем `digest`. Перед установкой
сверяют snapshot `Proxmox.current_configs('pve1')` с `Proxmox.config(vmid)`:
отпечатки обоих представлений должны совпасть. Это пример схемы, его placeholder
не является пригодным реестром.

Конфигурация должна принадлежать QEMU на указанном узле, без `template` и `lock`.
Адрес подтверждается через `ipconfigN`, CPU/RAM/SSD читаются из актуальных
`cores`, `memory`, `scsi0`. Несовпадение отпечатка или недоступная VM прекращает
мониторинг; оно никогда не снимает запрет изменений. Для намеренного изменения
служебной VM требуется отдельная root-процедура с проверкой и новым отпечатком.

Реестр устанавливают атомарно под exclusive lock существующего
`/var/lib/safehost-billing/operation.lock`. Provisioning-identity заказа 12,
client 16, allocation, описание VM, MAC, адреса и диски сохраняют. Для VM 101
заказ и allocation не создаются. Тариф/цена native-заказа 12 должны оставаться
нулевыми; настройки native renewal/expiry проверяются отдельно при rollout.
Реестр не создаёт финансовых заказов, платежей или согласий.

`monitor` возвращает дополнительный массив `infrastructure` с полями
`vmid,node,account,name,os,address,publicIpv4,status,phase,cores,memoryMb,diskGb,observedAt`.
`status` — `running` или `stopped`; `phase` — `ready` или `stopped`.
`observedAt` — UTC ISO timestamp. Отпечаток, конфигурация и credentials не
передаются. Native `status` дополнительно содержит boolean `infrastructure`.

AdminBridge принимает read action `infrastructure` с обычным проверенным
`actor`. Ответ `{servers:[...]}` строго ограничен совпадением `actor.account`;
параметры владельца из запроса не используются. Dashboard помечает строки
`infrastructure: true`, задаёт владельца из реестра и фактические ресурсы.
Совпавшая allocation сохраняет технический orderId; внешняя VM получает
`orderId: 0` только для отображения. Такой ID нельзя отправить в очередь.

Внутренний read action `mutation_guard` с `order_id/client_id` возвращает
`{mutable:true}` для обычного или ещё не выделенного заказа, а для служебной VM
отказывает. Он применяется до admin enqueue, worker effect и финансовых
callback. Engine повторно проверяет VMID в опасных методах. Запрещены create,
owner start/stop, suspend/unsuspend/cancel, все admin-команды, native renewal и
доступ к паролю. Освободившийся служебный VMID не выдаётся новому заказу.

Для rollout нужны `backend/engine.py` на Proxmox и файлы `AdminBridge.php`,
`EngineGateway.php`, `FinanceLifecycle.php`, `SafehostProxmox.php`,
`Safehostfinance/Service.php` в billing image
(`/opt/pilot`; установленный adapter также копируется в
`/var/www/html/library/Plugin/SafehostProxmox/SafehostProxmox.php` обычным installer).
Модуль pre-event guard также обновляют в `/var/www/html/modules/Safehostfinance/Service.php`.
Сначала обновляют engine, затем billing image/adapter и admin-worker, затем
устанавливают проверенный реестр. Read endpoint и dashboard проверяют после
установки. Существующие заказы, платежи и архивы не удаляются.
