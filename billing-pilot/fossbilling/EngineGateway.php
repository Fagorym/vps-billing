<?php
declare(strict_types=1);

/** Server-only adapter. This class is not a Servicecustom plugin. */
final class EngineGateway
{
    private function request(array $payload): array
    {
        $metrics = ($payload['action'] ?? '') === 'metrics';
        $argv = ['/usr/bin/ssh', '-T', '-i', '/run/proxmox/id_ed25519', '-o', 'IdentitiesOnly=yes',
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/run/proxmox/known_hosts',
            '-o', 'ConnectTimeout='.($metrics ? '3' : '10'), '-o', 'ServerAliveInterval='.($metrics ? '5' : '15'), '-o', 'ServerAliveCountMax=3', 'root@10.10.10.1'];
        set_time_limit($metrics ? 25 : 950);
        $process = proc_open($argv, [['pipe', 'r'], ['pipe', 'w'], ['file', '/dev/null', 'a']], $pipes);
        if (!is_resource($process)) { throw new RuntimeException('Engine unavailable'); }
        fwrite($pipes[0], json_encode($payload, JSON_THROW_ON_ERROR)); fclose($pipes[0]);
        if ($metrics) { [$output, $rc] = $this->metricsReply($process, $pipes[1]); }
        else {
            stream_set_timeout($pipes[1], 930);
            $output = stream_get_contents($pipes[1], 1048576); $meta = stream_get_meta_data($pipes[1]); fclose($pipes[1]);
            if ($meta['timed_out']) { proc_terminate($process); }
            $rc = proc_close($process);
        }
        $reply = json_decode($output ?: '', true);
        if ($rc !== 0 || !is_array($reply) || ($reply['ok'] ?? false) !== true) {
            if (($reply['code'] ?? '') === 'refused') { throw new DomainException('Operation refused by engine state or capacity checks'); }
            throw new RuntimeException('Engine temporarily unavailable');
        }
        if (!is_array($reply['result'] ?? null)) { throw new RuntimeException('Invalid engine response'); }
        return $reply['result'];
    }
    /** A wall-clock deadline, including partial output and a child that closes stdout early. */
    private function metricsReply($process, $stdout, float $seconds = 20): array
    {
        $deadline = microtime(true) + $seconds; $output = ''; $exit = -1;
        stream_set_blocking($stdout, false);
        try {
            while (true) {
                $chunk = fread($stdout, 65536);
                if ($chunk === false) { throw new RuntimeException('Metrics unavailable'); }
                $output .= $chunk;
                if (strlen($output) > 1048576) { throw new RuntimeException('Metrics response too large'); }
                $status = proc_get_status($process);
                if (!$status['running'] && feof($stdout)) { $exit = $status['exitcode']; break; }
                if (microtime(true) >= $deadline) { throw new RuntimeException('Metrics deadline exceeded'); }
                if ($chunk === '') { usleep(10000); }
            }
        } finally {
            if (proc_get_status($process)['running']) { proc_terminate($process, 9); }
            fclose($stdout); $closed = proc_close($process);
        }
        return [$output, $exit >= 0 ? $exit : $closed];
    }
    public function network(array $payload): array
    {
        if(!in_array($payload['action']??'', ['network_capacity','network_reserve','network_payment_pending','network_release_hold'],true))throw new InvalidArgumentException('Invalid network action');
        return $this->request($payload);
    }
    public function monitoring(): array { return $this->request(['action' => 'monitor']); }
    public function assertMutable(int $client, int $order): void
    {
        $result = $this->request(['action'=>'mutation_guard', 'client_id'=>$client, 'order_id'=>$order]);
        if (($result['mutable'] ?? false) !== true) { throw new DomainException('Infrastructure is read-only'); }
    }
    public function metrics(int $client, int $order, string $timeframe): array
    {
        return $this->request(['action'=>'metrics', 'client_id'=>$client, 'order_id'=>$order, 'timeframe'=>$timeframe]);
    }
    public function state(int $client,int $order): array
    {
        try{return $this->request(['action'=>'status','client_id'=>$client,'order_id'=>$order]);}
        catch(DomainException $e){throw new RuntimeException('Engine state temporarily unavailable');}
    }
    public function cancel(int $client,int $order): array {return $this->request(['action'=>'cancel','client_id'=>$client,'order_id'=>$order]);}
    public function ownerStatus(int $client, int $order): array
    {
        return $this->request(['action' => 'readiness', 'client_id' => $client, 'order_id' => $order]);
    }
    public function ownerPower(int $client, int $order, bool $start): array
    {
        return $this->request(['action' => $start ? 'owner_start' : 'owner_stop', 'client_id' => $client, 'order_id' => $order]);
    }
    public function action(array $order, string $command, array $request): array
    {
        $payload = ['action' => 'admin', 'order_id' => (int) $order['id'], 'client_id' => (int) $order['client_id'],
            'command' => $command, 'operation_id' => $request['operationId'], 'reason' => $request['reason'], 'actor' => $request['actor']];
        if ($command === 'purge') { $payload['confirm_vmid'] = $request['confirmVmid']; }
        return $this->request($payload);
    }
}
