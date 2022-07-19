<?php

declare(strict_types=1);

use Symfony\Component\Dotenv\Dotenv;

require __DIR__ . '/../vendor/autoload.php';

if (file_exists(dirname(__DIR__).'/config/bootstrap.php')) {
    require dirname(__DIR__).'/config/bootstrap.php';
} else {
    (new Dotenv())->bootEnv(dirname(__DIR__).'/.env', 'dev', []);
}

$requiredEnvs = [
    'TEST_TENANT_ID', 'TEST_CLIENT_ID', 'TEST_CLIENT_SECRET', 'TEST_KEY_VAULT_URL', 'TEST_AWS_REGION',
    'TEST_AWS_ACCESS_KEY_ID', 'TEST_AWS_SECRET_ACCESS_KEY', 'TEST_AWS_KMS_KEY_ID',
];

foreach ($requiredEnvs as $env) {
    if (empty(getenv($env))) {
        throw new Exception(sprintf('The "%s" environment variable is empty.', $env));
    }
}
