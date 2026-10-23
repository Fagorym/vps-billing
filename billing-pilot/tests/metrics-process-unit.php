<?php
declare(strict_types=1);
require '/opt/pilot/EngineGateway.php';
function checkMetrics(bool $condition): void { if (!$condition) { throw new RuntimeException('Metrics process assertion failed'); } }
$reader = new ReflectionMethod(EngineGateway::class, 'metricsReply');
$process = proc_open([PHP_BINARY, '-r', 'echo "complete";'], [['pipe','r'],['pipe','w'],['file','/dev/null','a']], $pipes);
fclose($pipes[0]);
[$output,$exit] = $reader->invoke(new EngineGateway(), $process, $pipes[1], 1.0);
checkMetrics($output === 'complete' && $exit === 0);
$file = tempnam(sys_get_temp_dir(), 'metrics-lock-');
$script = '$lock=fopen('.var_export($file,true).',"c");flock($lock,LOCK_SH);echo "partial";fclose(STDOUT);sleep(60);';
$process = proc_open([PHP_BINARY, '-r', $script], [['pipe','r'],['pipe','w'],['file','/dev/null','a']], $pipes);
fclose($pipes[0]); $started=microtime(true); $timedOut=false;
try { $reader->invoke(new EngineGateway(), $process, $pipes[1], .5); }
catch (RuntimeException $error) { $timedOut=$error->getMessage()==='Metrics deadline exceeded'; }
checkMetrics($timedOut && microtime(true)-$started < 2);
$lock=fopen($file,'c');checkMetrics(flock($lock,LOCK_EX|LOCK_NB));fclose($lock);unlink($file);
echo "PASS: metrics wall-clock deadline kills child, releases lock, accepts complete reply\n";
