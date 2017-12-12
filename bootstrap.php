<?php

if (file_exists(__DIR__ . '/config.php')) {
    require_once __DIR__ . '/config.php';
}

require_once __DIR__ . '/vendor/autoload.php';


defined('AWS_ACCESS_KEY_ID')
|| define('AWS_ACCESS_KEY_ID', getenv('AWS_ACCESS_KEY_ID') ?: 'key');

defined('AWS_SECRET_ACCESS_KEY')
|| define('AWS_SECRET_ACCESS_KEY', getenv('AWS_SECRET_ACCESS_KEY') ?: 'secret');

defined('AWS_DEFAULT_REGION')
|| define('AWS_DEFAULT_REGION', getenv('AWS_DEFAULT_REGION') ?: 'us-east-1');

defined('KMS_TEST_KEY')
|| define('KMS_TEST_KEY', getenv('KMS_TEST_KEY') ?: 'alias/foobar');
