<?php
declare(strict_types=1);

/** Only server-side code may call the native-money lifecycle endpoint. */
final class FinanceGateway
{
    public function exchange(array $request): array
    {
        $url=getenv('ADMIN_FINANCE_URL') ?: ''; $token=getenv('ADMIN_FINANCE_TOKEN') ?: '';
        $parts=parse_url($url); $scheme=$parts['scheme'] ?? ''; $host=$parts['host'] ?? '';
        if (!$parts || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || !in_array($scheme,['https','http'],true) || !$host
            || ($scheme==='http' && !in_array($host,['127.0.0.1','[::1]','localhost'],true))
            || strlen($token)<32 || preg_match('/[\r\n]/',$token)
            || hash_equals(getenv('PORTAL_BRIDGE_TOKEN') ?: '',$token)
            || hash_equals(getenv('ADMIN_PORTAL_BRIDGE_TOKEN') ?: '',$token)) {
            throw new RuntimeException('Finance integration unavailable');
        }
        $body=json_encode($request,JSON_THROW_ON_ERROR);
        $curl=curl_init($url);$reply='';
        curl_setopt_array($curl,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$body,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json','Authorization: Bearer '.$token],
            CURLOPT_CONNECTTIMEOUT=>3,CURLOPT_TIMEOUT=>20,CURLOPT_FOLLOWLOCATION=>false,
            CURLOPT_WRITEFUNCTION=>static function($handle,string $data)use(&$reply):int{
                if(strlen($reply)+strlen($data)>16384)return 0;$reply.=$data;return strlen($data);
            }]);
        $ok=curl_exec($curl);$status=(int)curl_getinfo($curl,CURLINFO_RESPONSE_CODE);curl_close($curl);
        if($status===409)throw new DomainException('Financial lifecycle permission denied');
        if($ok===false||$status!==200)throw new RuntimeException('Finance integration temporarily unavailable');
        $data=json_decode($reply,true);
        if(!is_array($data)||($data['ok']??false)!==true||!is_bool($data['paidService']??null)
            ||!in_array($data['state']??'', ['prepared','done'],true))throw new RuntimeException('Invalid finance response');
        return ['ok'=>true,'paidService'=>$data['paidService'],'state'=>$data['state']];
    }
}
