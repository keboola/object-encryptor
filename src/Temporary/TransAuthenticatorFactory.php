<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Temporary;

use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorInterface;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;

class TransAuthenticatorFactory extends AuthenticatorFactory
{
    public function getAuthenticator(GuzzleClientFactory $clientFactory, string $resource): AuthenticatorInterface
    {
        $authenticator = new TransClientCredentialsEnvironmentAuthenticator($clientFactory, $resource);
        try {
            $authenticator->checkUsability();
            return $authenticator;
        } catch (ClientException) {
            throw new TransClientNotAvailableException;
        }
    }
}
