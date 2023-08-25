<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;



use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Google\ApiCore\ApiException;
use Google\Cloud\Kms\V1\CryptoKey;
use Google\Cloud\Kms\V1\CryptoKey\CryptoKeyPurpose;
use Google\Cloud\Kms\V1\CryptoKeyVersion;
use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use Google\Cloud\Kms\V1\KeyRing;
use Keboola\AzureKeyVaultClient\Requests\SecretAttributes;
use Keboola\AzureKeyVaultClient\Requests\SetSecretRequest;
use Keboola\AzureKeyVaultClient\Responses\SecretBundle;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Retry\BackOff\ExponentialBackOffPolicy;
use Retry\Policy\SimpleRetryPolicy;
use Retry\RetryProxy;
use Throwable;

class GenericGKMWrapperTest extends AbstractTestCase
{
    /**
     * @return void
     *
     *
     * https://github.com/googleapis/google-cloud-php/blob/main/AUTHENTICATION.md
     *https://console.cloud.google.com/apis/credentials?hl=en&project=odin-dev-353408
     *https://cloud.google.com/php/docs/reference/cloud-kms/latest
     *
     */
    public function testRun(): void
    {
        $client = new KeyManagementServiceClient();

        $projectId = 'gcp-dev-353411';
        $location = 'global';

        // Create a keyring
        $keyRingId = 'odin-test';
        $locationName = $client::locationName($projectId, $location);
        $keyRingName = $client::keyRingName($projectId, $location, $keyRingId);

        try {
            $keyRing = $client->getKeyRing($keyRingName);
        } catch (ApiException $e) {
            if ($e->getStatus() === 'NOT_FOUND') {
                $keyRing = new KeyRing();
                $keyRing->setName($keyRingName);
                $client->createKeyRing($locationName, $keyRingId, $keyRing);
            }
        }

        // Create a cryptokey
        $keyId = 'odin-test';
        $keyName = $client::cryptoKeyName($projectId, $location, $keyRingId, $keyId);

        /*
        try {
            $cryptoKey = $client->getCryptoKey($keyName);
        } catch (ApiException $e) {
            var_dump($e);
            if ($e->getStatus() === 'NOT_FOUND') {
                $cryptoKey = new CryptoKey();
                $cryptoKey->setPurpose(CryptoKeyPurpose::ENCRYPT_DECRYPT);
                $cryptoKey = $client->createCryptoKey($keyRingName, $keyId, $cryptoKey);
            }
        }
        */


        // Encrypt and decrypt
        $secret = 'My secret text';
        $data = $secret;

        $this->metadata[self::KEY_STACK] = 'aconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comconnection.north-europe.azure.keboola.comz';
        $this->metadata[self::KEY_PROJECT] = 'a123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456z';
        $this->metadata[self::KEY_BRANCH_TYPE] = 'adegfreg34 g34 34g43 g43g 43g 43g 4 g34g 34 g43 43g 43 g4 g43 aultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultdefaultz';
        $this->metadata[self::KEY_CONFIGURATION] = 'a123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789z';
        $this->metadata[self::KEY_COMPONENT] = 'akeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboolakeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlkeboola.ex-db-mssqlz';
/*
        try {
            $key = Key::createNewRandomKey();
            $context = $this->encode([
                self::METADATA_INDEX => $this->metadata,
                self::KEY_INDEX => $key->saveToAsciiSafeString(),
            ]);
            $encryptedKey = $this->getRetryProxy()->call(function () use ($context, $client, $keyName) {
                $response = $client->encrypt(
                    $keyName, $context,
                );
                var_dump('strlen ' . strlen($response->getCiphertext()));
                return $response->getCiphertext();
            });
            $encryptedData = $this->encode([
                self::PAYLOAD_INDEX => Crypto::encrypt((string) $data, $key, true),
                self::CONTEXT_INDEX => $encryptedKey,
            ]);
        } catch (Throwable $e) {
            throw new ApplicationException('Ciphering failed: ' . $e->getMessage(), $e->getCode(), $e);
        }

        var_dump($encryptedData);





        $encrypted = $this->decode($encryptedData);
        if (!is_array($encrypted) || count($encrypted) !== 2 || empty($encrypted[self::PAYLOAD_INDEX]) ||
            empty($encrypted[self::CONTEXT_INDEX])
        ) {
            throw new UserException('Deciphering failed.');
        }

        var_dump($encrypted);
        try {
            $decryptedContext = $this->getRetryProxy()->call(function () use ($encrypted, $client, $keyName) {
                $response = $client->decrypt(
                    $keyName,
                    $encrypted[self::CONTEXT_INDEX],
                );
                return $response->getPlaintext();
            });
            assert(is_string($decryptedContext));
            $decryptedContext = $this->decode($decryptedContext);
            if (!is_array($decryptedContext) || (count($decryptedContext) !== 2) ||
                empty($decryptedContext[self::KEY_INDEX]) || !isset($decryptedContext[self::METADATA_INDEX]) ||
                !is_array($decryptedContext[self::METADATA_INDEX])
            ) {
                throw new ApplicationException('Deciphering failed.');
            }
        } catch (Throwable $e) {
            throw new ApplicationException('Deciphering failed.', $e->getCode(), $e);
        }
        var_dump($decryptedContext);

        var_dump($decryptedContext[self::METADATA_INDEX]);
        var_dump($this->metadata);

        try {
            $key = Key::loadFromAsciiSafeString($decryptedContext[self::KEY_INDEX]);
            $decrypted = Crypto::decrypt($encrypted[self::PAYLOAD_INDEX], $key, true);
        } catch (Throwable $e) {
            throw new ApplicationException('Deciphering failed.', $e->getCode(), $e);
        }
*/



                try {
                    $key = Key::createNewRandomKey();
                    $context = $this->encode([
                        self::METADATA_INDEX => $this->metadata,
                        self::KEY_INDEX => $key->saveToAsciiSafeString(),
                    ]);
                    $encryptedKey = $this->getRetryProxy()->call(function () use ($key, $client, $keyName) {
                        $response = $client->encrypt(
                            $keyName, $key->saveToAsciiSafeString(), ['additionalAuthenticatedData' => $this->encode($this->metadata)]
                        );
                        var_dump('strlen ' . strlen($response->getCiphertext()));
                        $name = $response->getName();
                        $parts = explode('/', $response->getName());
                        $version = array_pop($parts);
                        var_dump($version);
                        return $response->getCiphertext();
                    });
                    $encryptedData = $this->encode([
                        self::PAYLOAD_INDEX => Crypto::encrypt((string) $data, $key, true),
                        self::KEY_INDEX => $encryptedKey,
                    ]);
                } catch (Throwable $e) {
                    throw new ApplicationException('Ciphering failed: ' . $e->getMessage(), $e->getCode(), $e);
                }

                var_dump($encryptedData);

$encryptedData = 'eJwBXAGj/mE6Mjp7aToyO3M6OTg6It71AgDZYKYEfld7E37DOT1Ehel+odgwZpOlGCtx9qXzDXUfcuK1pJk2Jb1zHHIkbjOEI4aGlEttQFGqRp8uaPW1bKyU1KtFzNMYVdgAqs1h873lFRG9H/DBhPHDPHNsRbHwIjtpOjE7czoyMTk6IgokAMzsAapE+GxjNFJV/wouh6LzqFffC7T+yAqojTAbZZsJt/91ErIBAF6ZWmqCbSsrGkeu4AQP6oZzugTZ3AXP9f8wBvf/AXwFT191CBlRM8N3IDPul4oWaEdFcY+pgYiY1gfXkxlH47o0JloXATyykOPDmUMDcBeuKxoAipjBcrC57aiHCBnFobERzPXKZ2kAjYt5sEOGN/OUDYPiMnZbYZCk1xP1p36iqBJa1EsHxxWDkuuKUmi4ZWQKbACsZRG7s5gVh76YXoqaZBkO5XQ02fdV1Ep/SdLZCiI7feWNnNI=';


        # $this->metadata[self::KEY_STACK] = 'aconnection.north-europe.azure.keboola.comz';


                $encrypted = $this->decode($encryptedData);
                if (!is_array($encrypted) || count($encrypted) !== 2 || empty($encrypted[self::PAYLOAD_INDEX]) ||
                    empty($encrypted[self::KEY_INDEX])
                ) {
                    throw new UserException('Deciphering failed.');
                }

                var_dump($encrypted);
                try {
                    $decryptedKey = $this->getRetryProxy()->call(function () use ($encrypted, $client, $keyName) {
                        $response = $client->decrypt(
                            $keyName,
                            $encrypted[self::KEY_INDEX],
                            ['additionalAuthenticatedData' => $this->encode($this->metadata)]
                        );
                        return $response->getPlaintext();
                    });
                    assert(is_string($decryptedKey));

                } catch (Throwable $e) {
                    throw new ApplicationException('Deciphering failed.', $e->getCode(), $e);
                }
                //var_dump($decryptedKey);

                //var_dump($this->metadata);

                try {
                    $key = Key::loadFromAsciiSafeString($decryptedKey);
                    $decrypted = Crypto::decrypt($encrypted[self::PAYLOAD_INDEX], $key, true);
                } catch (Throwable $e) {
                    throw new ApplicationException('Deciphering failed.', $e->getCode(), $e);
                }

        self::assertSame($secret, $decrypted);
    }

    /**
     * @param mixed $data
     */
    private function encode($data): string
    {
        return base64_encode((string) gzcompress(serialize($data)));
    }

    /**
     * @return mixed
     * @throws UserException
     */
    private function decode(string $data)
    {
        try {
            return @unserialize((string) gzuncompress((string) base64_decode($data)));
        } catch (Throwable $e) {
            throw new UserException('Deciphering failed.', 0, $e);
        }
    }

    // internal indexes in cipher structures
    private const METADATA_INDEX = 0;
    private const KEY_INDEX = 1;
    private const PAYLOAD_INDEX = 2;

    private const KEY_VERSION_INDEX = 5;
    private const SECRET_NAME = 3;
    private const SECRET_VERSION = 4;

    private const CONTEXT_INDEX = 3;
    // private const KEY_INDEX = 3;

    private const KEY_STACK = 'stackId';
    private const KEY_PROJECT = 'projectId';

    private const KEY_BRANCH_TYPE = 'branchType';
    private const KEY_CONFIGURATION = 'configurationId';

    private const KEY_COMPONENT = 'componentId';


    private array $metadata = [];

    private function getRetryProxy(): RetryProxy
    {
        $retryPolicy = new SimpleRetryPolicy(3);
        $backOffPolicy = new ExponentialBackOffPolicy(1000);
        return new RetryProxy($retryPolicy, $backOffPolicy);
    }

}
