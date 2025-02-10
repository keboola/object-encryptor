<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Temporary;

use Keboola\AzureKeyVaultClient\Authentication\ClientCredentialsEnvironmentAuthenticator;

class TransClientCredentialsEnvironmentAuthenticator extends ClientCredentialsEnvironmentAuthenticator
{
    protected const ENV_AZURE_TENANT_ID = 'TRANS_AZURE_TENANT_ID';
    protected const ENV_AZURE_CLIENT_ID = 'TRANS_AZURE_CLIENT_ID';
    protected const ENV_AZURE_CLIENT_SECRET = 'TRANS_AZURE_CLIENT_SECRET';
}
