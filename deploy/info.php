<?php

/////////////////////////////////////////////////////////////////////////////
// General information
/////////////////////////////////////////////////////////////////////////////

$app['basename'] = 'ldap';
$app['version'] = '1.6.8';
$app['release'] = '1';
$app['vendor'] = 'ClearFoundation';
$app['packager'] = 'ClearFoundation';
$app['license'] = 'GPLv3';
$app['license_core'] = 'LGPLv3';
$app['description'] = lang('ldap_app_description');

/////////////////////////////////////////////////////////////////////////////
// App name and categories
/////////////////////////////////////////////////////////////////////////////

$app['name'] = lang('ldap_app_name');
$app['category'] = lang('base_category_system');
$app['subcategory'] = lang('base_subcategory_settings');
$app['menu_enabled'] = FALSE;

/////////////////////////////////////////////////////////////////////////////
// Packaging
/////////////////////////////////////////////////////////////////////////////

$app['core_only'] = TRUE;

$app['core_requires'] = array(
    'app-mode-core',
    'openssl',
    'system-ldap-driver', 
    'webconfig-php-ldap',
);

$app['core_directory_manifest'] = array(
   '/var/clearos/ldap' => array(),
   '/var/clearos/ldap/synchronize' => array(),
);

$app['core_file_manifest'] = array(
    'nslcd.php'=> array('target' => '/var/clearos/base/daemon/nslcd.php'),
    'prestart-ldap' => array(
        'target' => '/usr/sbin/prestart-ldap',
        'mode' => '0755',
    ),
    'poststart-ldap' => array(
        'target' => '/usr/sbin/poststart-ldap',
        'mode' => '0755',
    ),
    'ldap-init' => array(
        'target' => '/usr/sbin/ldap-init',
        'mode' => '0755',
    ),
    'ldap-synchronize' => array(
        'target' => '/usr/sbin/ldap-synchronize',
        'mode' => '0755',
    ),
);
