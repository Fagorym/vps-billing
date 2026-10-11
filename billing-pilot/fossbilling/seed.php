<?php
declare(strict_types=1);
$completed = false;
register_shutdown_function(static function () use (&$completed): void { if (!$completed) { exit(1); } });

chdir('/var/www/html');
// CLI-only bootstrap, no admin API token is exposed to the client side.
require 'load.php';
$di['translate']();
$di['loggedin_admin'] = $di['db']->getExistingModelById('Admin', 1);
$api = $di['api_admin'];
function optionalSshKey($api, int $formId): void {
    foreach ($api->formbuilder_get_form_fields(['form_id' => $formId]) as $field) {
        if ($field['name'] !== 'ssh_key') { continue; }
        $field['label'] = 'Публичный SSH-ключ (необязательно)';
        $field['description'] = 'Оставьте пустым для входа по временному паролю. Для входа по ключу вставьте ssh-ed25519 из файла .pub.';
        $field['required'] = 0;
        $field['options'] = json_decode($field['options'] ?? '', true) ?: [];
        // Keep the existing textarea type; updateField otherwise requires editor-specific size arrays.
        unset($field['type']);
        $api->formbuilder_update_field($field);
        return;
    }
    throw new RuntimeException('Поле SSH-ключа пилота не найдено');
}
$api->extension_config_save(['ext' => 'email', 'mailer' => 'custom', 'custom_dsn' => 'null://null']);
if (is_file('/var/www/html/data/pilot-catalog.json')) {
    $catalog = json_decode(file_get_contents('/var/www/html/data/pilot-catalog.json'), true, 512, JSON_THROW_ON_ERROR);
    optionalSshKey($api, (int) $catalog['form_id']);
    echo "Каталог пилота уже создан\n";
    $completed = true;
    exit(0);
}
$plans = json_decode(file_get_contents('/opt/pilot/config.json'), true, 512, JSON_THROW_ON_ERROR)['plans'];
// Formbuilder is a core module in 0.8.8 and must not be installed/activated via Extension API.
$forms = $api->formbuilder_get_pairs();
$formId = array_search('Safehost TEST: SSH key', $forms, true);
if ($formId === false) {
    $formId = $api->formbuilder_create_form(['name' => 'Safehost TEST: SSH key']);
    $api->formbuilder_add_field(['form_id' => $formId, 'type' => 'textarea', 'name' => 'ssh_key',
        'label' => 'Публичный SSH-ключ (необязательно)', 'required' => 0,
        'description' => 'Оставьте пустым для временного пароля. Для входа по ключу вставьте ssh-ed25519 из файла .pub.']);
}
optionalSshKey($api, (int) $formId);
$result = ['form_id' => (int) $formId, 'products' => []];
foreach ($plans as $name => $plan) {
    $slug = 'pilot-vps-' . $name;
    $product = $di['em']->getRepository(\Box\Mod\Product\Entity\Product::class)->findOneBy(['slug' => $slug]);
    if ($product !== null) {
        if ($product->getPlugin() !== 'SafehostProxmox' || $product->getType() !== 'custom') {
            throw new RuntimeException('Slug занят чужим продуктом: ' . $slug);
        }
        $id = $product->getId();
    } else {
        $id = $api->product_prepare(['title' => 'VPS ' . ucfirst($name) . ' — TEST', 'type' => 'custom']);
        $api->product_update(['id' => $id, 'slug' => $slug, 'status' => 'enabled', 'hidden' => false,
            'plugin' => 'SafehostProxmox', 'form_id' => (int) $formId, 'setup' => 'after_payment',
            'description' => $plan['cores'] . ' vCPU / ' . ($plan['memory_mb'] / 1024) . ' GiB / ' . $plan['disk_gb'] . ' GiB. Ubuntu 24.04, NAT, доступ по SSH. Тестовые счета: деньги не списываются.',
            'pricing' => ['type' => 'recurrent', 'recurrent' => ['1M' => ['enabled' => true, 'price' => $plan['price'], 'setup' => 0]]]]);
        $product = $di['mod_service']('product')->findProductById((int) $id);
    }
    // plugin_config is a separate admin-owned field in 0.8.8, not customer order config.
    $product->setPluginConfig(json_encode(['plan' => $name], JSON_THROW_ON_ERROR));
    $di['em']->flush();
    $result['products'][$name] = (int) $id;
}
$gateways = $api->invoice_gateway_get_list(['per_page' => 100]);
$custom = null;
foreach ($gateways['list'] as $gateway) {
    if ($gateway['code'] === 'Custom') {
        $custom = $gateway['id'];
    } elseif ($gateway['enabled']) {
        throw new RuntimeException('Найден другой включённый шлюз: тестовый режим не подтверждён');
    }
}
if ($custom === null) {
    $api->invoice_gateway_install(['code' => 'Custom']);
    $gateways = $api->invoice_gateway_get_list(['per_page' => 100]);
    foreach ($gateways['list'] as $gateway) {
        if ($gateway['code'] === 'Custom') {
            $custom = $gateway['id'];
        }
    }
}
if ($custom === null) {
    throw new RuntimeException('Custom gateway не установлен');
}
$api->invoice_gateway_update(['id' => $custom, 'title' => 'ТЕСТ — без списаний', 'enabled' => true,
    'test_mode' => true, 'allow_single' => true, 'allow_recurrent' => false, 'accepted_currencies' => ['RUB'],
    'config' => ['single' => '<p>Это тестовый счёт. Ничего не переводите. Администратор подтверждает тестовую оплату вручную.</p>']]);
$result['gateway_id'] = (int) $custom;
file_put_contents('/var/www/html/data/pilot-catalog.json', json_encode($result, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
echo "Каталог VPS и тестовая оплата настроены; исходящие письма отключены\n";
$completed = true;
