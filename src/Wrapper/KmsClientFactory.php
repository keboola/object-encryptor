<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Aws\Credentials\CredentialProvider;
use Aws\Kms\KmsClient;
use Aws\Sts\StsClient;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;

class KmsClientFactory
{
    private const CONNECT_TIMEOUT = 10;
    private const CONNECT_RETRIES = 5;
    private const TRANSFER_TIMEOUT = 120;

    public function createClient(EncryptorOptions $encryptorOptions): KmsClient
    {
        $region = $encryptorOptions->getKmsKeyRegion();
        if ($region === null) {
            throw new ApplicationException('Cipher key settings are missing.');
        }

        $role = $encryptorOptions->getKmsRole();

        $stsClient = new StsClient([
            'region' => $region,
            'version' => '2011-06-15',
            'retries' => self::CONNECT_RETRIES,
            'http' => [
                'connect_timeout' => self::CONNECT_TIMEOUT,
                'timeout' => self::TRANSFER_TIMEOUT,
            ],
        ]);

        if ($role) {
            $credentials = CredentialProvider::memoize(
                CredentialProvider::assumeRole([
                    'client' => $stsClient,
                    'assume_role_params' => [
                        'RoleArn' => $role,
                        'RoleSessionName' => 'Encrypt-Decrypt',
                    ],
                ]),
            );
        } else {
            $credentials = CredentialProvider::defaultProvider([
                'region' => $region,
                'stsClient' => $stsClient,
            ]);
        }

        return new KmsClient([
            'region' => $region,
            'version' => '2014-11-01',
            'retries' => self::CONNECT_RETRIES,
            'http' => [
                'connect_timeout' => self::CONNECT_TIMEOUT,
                'timeout' => self::TRANSFER_TIMEOUT,
            ],
            'credentials' => $credentials,
        ]);
    }
}
