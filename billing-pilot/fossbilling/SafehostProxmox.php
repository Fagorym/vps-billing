<?php
declare(strict_types=1);

/** FOSSBilling 0.8.8 Custom product plugin. Credentials never come from order data. */
class SafehostProxmox
{
    public function __construct(private array $config = []) {}

    public function activate(array $data, array $order, array $params = []): bool
    {
        $this->assertLifecycle($params);
        $this->finance()->check($order,'activate');
        $this->request('create', $order, [
            'plan' => $this->config['plan'] ?? '',
            'disk_gb' => $data['disk_gb'] ?? null,
            'ssh_key' => $data['ssh_key'] ?? '',
            'network_mode'=>$data['network_mode']??'nat', 'lease_id'=>$data['lease_id']??null,
            'account'=>$data['account']??null,'reference'=>$data['reference']??null,
        ]);
        return true;
    }

    public function suspend(array $data, array $order, array $params = []): bool
    {
        $this->assertLifecycle($params);
        $this->request('suspend', $order);
        return true;
    }

    public function unsuspend(array $data, array $order, array $params = []): bool
    {
        $this->assertLifecycle($params);
        $this->finance()->check($order,'unblock');
        $this->request('unsuspend', $order);
        return true;
    }

    public function cancel(array $data, array $order, array $params = []): bool
    {
        $this->assertLifecycle($params);
        $this->finance()->native($order,'cancel',fn()=>$this->request('cancel',$order));
        return true;
    }

    public function delete(array $data, array $order, array $params = []): bool
    {
        $this->assertLifecycle($params);
        $this->finance()->native($order,'delete',fn()=>$this->request('cancel',$order));
        return true; // No qm destroy: disk and allocation remain.
    }

    public function renew(array $data, array $order, array $params = []): bool
    {
        $this->assertLifecycle($params);
        $this->request('status', $order);
        return true;
    }

    public function uncancel(array $data, array $order, array $params = []): bool
    {
        $this->assertLifecycle($params);
        throw new \FOSSBilling\InformationException('Отменённый VPS сохранён. Автоматический запуск после отмены запрещён.');
    }

    public function connection(array $data, array $order, array $params = []): array
    {
        // Servicecustom/Api/Client checks authenticated ownership of order_id first.
        return $this->request('status', $order);
    }

    public function initial_password(array $data, array $order, array $params = []): array
    {
        // The core checks the authenticated client's ownership before calling this method.
        if ($order['status'] !== 'active') {
            throw new \FOSSBilling\InformationException('Пароль доступен только у активной услуги.');
        }
        return $this->request('password', $order);
    }

    public function readiness(array $data, array $order, array $params = []): array
    {
        return $this->request('readiness', $order);
    }

    private function assertLifecycle(array $params): void
    {
        // Pinned 0.8.8: lifecycle callOnAdapter supplies []. Client/Admin customCall
        // always supplies the complete API data (order_id + method at minimum).
        // PHP method names are case-insensitive; the core's lowercase denylist is not.
        if ($params !== []) {
            throw new \FOSSBilling\InformationException('Операция доступна только обработчику заказа, не через Custom call.');
        }
    }
    private function finance(): FinanceLifecycle
    {
        require_once '/opt/pilot/FinanceLifecycle.php';return FinanceLifecycle::runtime();
    }

    private function request(string $action, array $order, array $extra = []): array
    {
        $payload = array_merge($extra, [
            'action' => $action,
            'order_id' => (int) $order['id'],
            'client_id' => (int) $order['client_id'],
        ]);
        $argv = ['/usr/bin/ssh', '-T', '-i', '/run/proxmox/id_ed25519',
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=/run/proxmox/known_hosts', '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', 'root@10.10.10.1'];
        set_time_limit(950);
        $process = proc_open($argv, [['pipe', 'r'], ['pipe', 'w'], ['file', '/dev/null', 'a']], $pipes);
        if (!is_resource($process)) {
            throw new \FOSSBilling\InformationException('Не удалось запустить адаптер Proxmox');
        }
        fwrite($pipes[0], json_encode($payload, JSON_THROW_ON_ERROR));
        fclose($pipes[0]);
        stream_set_timeout($pipes[1], 930);
        $output = stream_get_contents($pipes[1], 16384);
        $meta = stream_get_meta_data($pipes[1]);
        fclose($pipes[1]);
        if ($meta['timed_out']) {
            proc_terminate($process);
        }
        $rc = proc_close($process);
        $response = json_decode($output ?: '', true);
        if ($rc !== 0 || !is_array($response) || ($response['ok'] ?? false) !== true) {
            throw new \FOSSBilling\InformationException($response['error'] ?? 'Адаптер недоступен. Повторите активацию того же заказа: второй VPS не создаётся.');
        }
        return $response['result'];
    }
}
