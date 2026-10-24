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

Для истории CPU/RAM/сети нужен отдельный root-private файл
`/var/lib/safehost-billing/infrastructure-metrics.json` (обычный файл root:root
`0600` в root:root каталоге `0700`). Исходная строгая схема и байты
`infrastructure.json` при включении истории не меняются. Схема sidecar:

```json
{
  "version": 1,
  "servers": [
    {
      "vmid": 101,
      "node": "pve1",
      "account": "9ac2de9e-e907-42f1-b28d-e65a2c1552a8",
      "configSha256": "<тот же SHA-256, что в infrastructure.json>",
      "metricsSince": "2026-10-23T15:03:37.493879+00:00"
    }
  ]
}
```

Каждая запись содержит ровно эти пять полей и уникальный VMID; все четыре поля
идентичности должны совпасть с текущим основным реестром. `metricsSince` —
доверенный UTC ISO timestamp подтверждённой регистрации текущей VM (`Z` или
`+00:00`, не раньше Unix epoch и не в будущем). Отсутствующий, повреждённый или
небезопасный sidecar блокирует только историю служебных VM; monitor, запрет
изменений и обычные metrics его не читают. Старые engine также игнорируют sidecar.

`infrastructure_metrics` принимает проверенный `actor`, `vmid`, `node`,
`timeframe: day|week`; владелец берётся только из `actor.account`. Engine повторно
читает и сверяет обе записи и Proxmox fingerprint до и после RRD. Любое изменение
владельца, узла, отпечатка или cutoff прекращает запрос. Bucket, пересекающий
`metricsSince`, исключается: нижняя граница равна `max(начало периода,
metricsSince + размер bucket)`. Allocation/client/order не используются для этой
истории; полный monitor не вызывается.

`infrastructure_disk` принимает тот же проверенный `actor`, `vmid`, `node` без
периода и возвращает `{vmid,node,account,mountpoint:"/",usedBytes,totalBytes,observedAt}`.
Один ограниченный identity reader проверяет регистрацию и Proxmox fingerprint
до и после существующего QGA `get-fsinfo` (timeout 3 секунды); RRD history и
полный monitor не вызываются. Доступны только целые числа без boolean:
`0 <= usedBytes <= totalBytes`, `0 < totalBytes <= 2**53-1`. При недоступном QGA,
timeout или неверных размерах `usedBytes`, `totalBytes`, `observedAt` равны `null`.
Нулевой used допустим только при подтверждённом положительном total. Оба root
реестра остаются неизменными; sidecar истории для чтения диска не требуется.

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

История root filesystem собирается только отдельным root collector через
`safehost-infrastructure-disk.timer` раз в UTC-минуту (`Persistent=false`).
Collector использует standalone `InfrastructureObserver(state,pve)` и никогда
не создаёт Engine/allocator connection. Он берёт shared nonblocking operation
lock до чтения config/seal, отдельный collector lock и общий deadline15s; QGA
ограничен3s. Фиксированный allowlist collector —101/1101. Новые registry VMID
автоматически не собираются. Поздний результат, пересёкший минутную границу,
отбрасывается; повтор одной минуты не заменяет первый sample.

Отдельный store `/var/lib/safehost-monitoring/infrastructure-disk.sqlite3`
содержит восемь дней минутных snapshots с ключом
`account,vmid,node,configSha256,timestamp`. Каталог root0700, DB/WAL/SHM/lock
root0600, symlinks запрещены. Только collector создаёт/пишет/prune store.
Исторические финансовые данные, allocations и оба root-реестра не меняются.

`infrastructure_disk_history` принимает actor,vmid,node,timeframe:day|week;
engine payload содержит только action,account,vmid,node,timeframe. Чтение идёт
через Observer до создания Engine, с config seal и registry/config identity
до/после readonly SQL. QGA и RRD history при этом не вызываются. Store открывается
`mode=ro`; отсутствующий store не создаётся. Ответ:
`{vmid,node,account,mountpoint:"/",timeframe,start,end,step:60,points:[{timestamp,usedBytes,totalBytes}]}`.
`end` — текущая UTC-минута, `start=end-duration`; ticks `(start,end]` дают ровно
1440/10080 точек. Пропуск/ошибка/время до первого sample представлены null-парой;
нет backfill, interpolation, усреднения или переноса последнего значения.
Неделя с максимальными safe-int значениями укладывается в transport limit1MiB.

Ansible воспроизводимо копирует оба новых модуля перед engine и unit definitions,
но не включает timer. Scoped rollout включает его только после source/API/store
preflight; rollback отключает timer и сохраняет monitoring DB без delete/restore.
