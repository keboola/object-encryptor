<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Throwable;

class GkmsClientFactory
{
    public function createClient(EncryptorOptions $encryptorOptions): KeyManagementServiceClient
    {
        /* It seems that KeyManagementServiceClient client does not accept retrySettings configuration
            (as some other GCP clients do), therefore we disable retries completely and rely on application level
            retries in GenericGKMWrapper. */
        try {
            // GKM client checks for authorization when created, authorization is cached in memory
            return new KeyManagementServiceClient(
                [
                    'disableRetries' => true,
                ]
            );
        } catch (Throwable $e) {
            throw new ApplicationException('Cipher key settings are invalid: ' . $e->getMessage(), 0, $e);
        }
    }
}
