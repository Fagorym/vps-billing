<?php
declare(strict_types=1);
namespace Box\Mod\Safehostfinance;

/** Before-delete is outside core's forceDelete catch; adapter guards also cover skipEvent. */
final class Service implements \FOSSBilling\InjectionAwareInterface
{
    protected ?\Pimple\Container $di=null;
    public function setDi(\Pimple\Container $di):void{$this->di=$di;}
    public function getDi():?\Pimple\Container{return $this->di;}
    private static function context(\Box_Event $event):?array
    {
        $di=$event->getDi();$order=$di['db']->getExistingModelById('ClientOrder',(int)$event['id']);
        require_once '/opt/pilot/FinanceLifecycle.php';$finance=\FinanceLifecycle::fromDi($di);
        $plugin=$di['em']->getConnection()->fetchOne('SELECT p.plugin FROM client_order o JOIN product p ON p.id=o.product_id WHERE o.id=?',[(int)$event['id']]);
        if($plugin!=='SafehostProxmox'&&!$finance->ownsPortalOrder((int)$event['id']))return null;
        $data=$di['mod_service']('order')->toApiArray($order);
        return ['finance'=>$finance,'order'=>$data];
    }
    private static function guard(\Box_Event $event,string $command):void
    {
        $context=self::context($event);
        if($context!==null)$context['finance']->prepareNative($context['order'],$command);
    }
    private static function mutable(\Box_Event $event):void
    {
        $context=self::context($event);
        if($context!==null)$context['finance']->assertMutable($context['order']);
    }
    public static function onBeforeAdminOrderDelete(\Box_Event $event):void{self::guard($event,'delete');}
    public static function onBeforeAdminOrderCancel(\Box_Event $event):void{self::guard($event,'cancel');}
    public static function onBeforeAdminOrderActivate(\Box_Event $event):void{self::mutable($event);}
    public static function onBeforeAdminOrderRenew(\Box_Event $event):void{self::mutable($event);}
    public static function onBeforeAdminOrderSuspend(\Box_Event $event):void{self::mutable($event);}
    public static function onBeforeAdminOrderUnsuspend(\Box_Event $event):void{self::mutable($event);}
    public static function onBeforeAdminOrderUncancel(\Box_Event $event):void{self::mutable($event);}
    public static function onBeforeAdminOrderUpdate(\Box_Event $event):void{self::mutable($event);}
}
