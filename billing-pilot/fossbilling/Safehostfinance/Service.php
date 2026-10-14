<?php
declare(strict_types=1);
namespace Box\Mod\Safehostfinance;

/** Before-delete is outside core's forceDelete catch; adapter guards also cover skipEvent. */
final class Service implements \FOSSBilling\InjectionAwareInterface
{
    protected ?\Pimple\Container $di=null;
    public function setDi(\Pimple\Container $di):void{$this->di=$di;}
    public function getDi():?\Pimple\Container{return $this->di;}
    private static function guard(\Box_Event $event,string $command):void
    {
        $di=$event->getDi();$order=$di['db']->getExistingModelById('ClientOrder',(int)$event['id']);
        require_once '/opt/pilot/FinanceLifecycle.php';$finance=\FinanceLifecycle::fromDi($di);
        $plugin=$di['em']->getConnection()->fetchOne('SELECT p.plugin FROM client_order o JOIN product p ON p.id=o.product_id WHERE o.id=?',[(int)$event['id']]);
        if($plugin!=='SafehostProxmox'&&!$finance->ownsPortalOrder((int)$event['id']))return;
        $data=$di['mod_service']('order')->toApiArray($order);
        $finance->prepareNative($data,$command);
    }
    public static function onBeforeAdminOrderDelete(\Box_Event $event):void{self::guard($event,'delete');}
    public static function onBeforeAdminOrderCancel(\Box_Event $event):void{self::guard($event,'cancel');}
}
