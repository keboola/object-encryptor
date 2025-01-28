<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Temporary;

use Keboola\AzureKeyVaultClient\Client;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;

class TransClient extends Client
{
    public function __construct(GuzzleClientFactory $clientFactory, ?string $encryptorId)
    {
        $vaultBaseUrl = (string) getenv(self::determinateVaultUrlEnvName($encryptorId));

        if ($vaultBaseUrl === '') {
            throw new TransClientNotAvailableException;
        }

        parent::__construct(
            $clientFactory,
            new TransAuthenticatorFactory(),
            $vaultBaseUrl,
        );
    }

    public static function determinateVaultUrlEnvName(?string $encryptorId): string
    {
        $transEnvName = 'TRANS_AZURE_KEY_VAULT_URL';

        if (!empty($encryptorId)) { // not null or empty string
            $suffix = (string) preg_replace('/[\s\-_]+/', '_', $encryptorId);
            $suffix = trim($suffix, '_');
            $transEnvName .= sprintf('_%s', strtoupper($suffix));
        }

        return $transEnvName;
    }
}
