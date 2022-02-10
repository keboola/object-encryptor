<?php

namespace Keboola\ObjectEncryptor\Tests;

use Aws\CommandInterface;
use Aws\Kms\KmsClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use PHPUnit\Framework\TestCase;

class GenericKMSWrapperTest extends TestCase
{
    use DataProviderTrait;

    public function setUp()
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY='. getenv('TEST_AWS_SECRET_ACCESS_KEY'));
    }

    /**
     * @return GenericKMSWrapper
     */
    private function getWrapper()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        return $wrapper;
    }

    public function testEncrypt()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptWrongKey()
    {
        $wrapper = $this->getWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        // This is ok, because KMS key is found automatically during decryption
        $wrapper->setKMSKeyId('non-existent');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @dataProvider emptyValuesProvider()
     * @param $secret
     * @throws ApplicationException
     * @throws UserException
     */
    public function testEncryptEmptyValue($secret)
    {
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testRetryEncrypt()
    {
        $mockKmsClient = self::getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([['region' => getenv('TEST_AWS_REGION'), 'version' => '2014-11-01', 'service' => 'kms']])
            ->setMethods(['execute'])
            ->getMock();
        $callNo = 0;
        $mockKmsClient->method('execute')
            ->willReturnCallback(function (CommandInterface $command) use (&$callNo, $mockKmsClient) {
                $callNo++;
                if ($callNo < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    /** @var KmsClient $mockKmsClient */
                    return $mockKmsClient->executeAsync($command)->wait();
                }
            });

        /** @var \PHPUnit_Framework_MockObject_MockObject $mockWrapper */
        $mockWrapper = self::getMockBuilder(GenericKMSWrapper::class)
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $mockWrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        $encrypted = $mockWrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $mockWrapper->decrypt($encrypted));
    }

    public function testRetryEncryptFail()
    {
        $mockKmsClient = self::getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([['region' => getenv('TEST_AWS_REGION'), 'version' => '2014-11-01', 'service' => 'kms']])
            ->setMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri'))
            );

        /** @var \PHPUnit_Framework_MockObject_MockObject $mockWrapper */
        $mockWrapper = self::getMockBuilder(GenericKMSWrapper::class)
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $mockWrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: Failed to obtain encryption key.');
        $mockWrapper->encrypt($secret);
    }

    public function testRetryDecrypt()
    {
        $mockKmsClient = self::getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([['region' => getenv('TEST_AWS_REGION'), 'version' => '2014-11-01', 'service' => 'kms']])
            ->setMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willReturnCallback(function (CommandInterface $command) use (&$callNo, $mockKmsClient) {
                $callNo++;
                if ($callNo < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    /** @var KmsClient $mockKmsClient */
                    return $mockKmsClient->executeAsync($command)->wait();
                }
            });

        /** @var \PHPUnit_Framework_MockObject_MockObject $mockWrapper */
        $mockWrapper = self::getMockBuilder(GenericKMSWrapper::class)
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $mockWrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        self::assertEquals($secret, $mockWrapper->decrypt($encrypted));
    }

    public function testRetryDecryptFail()
    {
        $mockKmsClient = self::getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([['region' => getenv('TEST_AWS_REGION'), 'version' => '2014-11-01', 'service' => 'kms']])
            ->setMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri'))
            );

        /** @var \PHPUnit_Framework_MockObject_MockObject $mockWrapper */
        $mockWrapper = self::getMockBuilder(GenericKMSWrapper::class)
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $mockWrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $mockWrapper->decrypt($encrypted);
    }

    public function testEncryptNonScalar()
    {
        $secret = ['a' => 'b'];
        $wrapper = $this->getWrapper();
        self::expectException(UserException::class);
        self::expectExceptionMessage('Cannot encrypt a non-scalar value');
        /** @noinspection PhpParamsInspection */
        $wrapper->encrypt($secret);
    }

    public function testEncryptMetadata()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptMetadataCacheHit()
    {
        $secret1 = 'mySecretValue1';
        $secret2 = 'mySecretValue2';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted1 = $wrapper->encrypt($secret1);
        self::assertNotEquals($secret1, $encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $encrypted2 = $wrapper->encrypt($secret2);
        self::assertNotEquals($secret2, $encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $wrapper->decrypt($encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $wrapper->decrypt($encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));
    }

    public function testEncryptMetadataCacheMiss()
    {
        $secret1 = 'mySecretValue1';
        $secret2 = 'mySecretValue2';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key1', 'value1');
        $encrypted1 = $wrapper->encrypt($secret1);
        self::assertNotEquals($secret1, $encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $wrapper->setMetadataValue('key2', 'value2');
        $encrypted2 = $wrapper->encrypt($secret2);
        self::assertNotEquals($secret2, $encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key1', 'value1');
        $wrapper->decrypt($encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $wrapper->setMetadataValue('key2', 'value2');
        $wrapper->decrypt($encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));
    }

    public function testEncryptMetadataMismatchNoMetadata()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testEncryptMetadataMismatchBadMetadata()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value-bad');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupEncryptMissingAll()
    {
        $wrapper = new GenericKMSWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncryptMissingKeyId()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSRegion('my-region');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncryptMissingRegion()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId('my-key');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptMissingAll()
    {
        $wrapper = new GenericKMSWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptMissingKeyId()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSRegion('my-region');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptMissingRegion()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId('my-key');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidKeyId()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(new \stdClass());
        $wrapper->setKMSRegion('my-region');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidRegion()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId('my-key');
        /** @noinspection PhpParamsInspection */
        $wrapper->setKMSRegion(['a' => 'b']);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidCredentials()
    {
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY=some-garbage');
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: Failed to obtain encryption key.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidNonExistentRegion()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion('non-existent');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: Failed to obtain encryption key.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @dataProvider invalidCipherProvider()
     * @param string $cipher
     * @param string $message
     * @throws ApplicationException
     * @throws UserException
     */
    public function testDecryptInvalidCiphers($cipher, $message)
    {
        $wrapper = $this->getWrapper();
        self::expectException(UserException::class);
        self::expectExceptionMessage($message);
        $wrapper->decrypt($cipher);
    }
}
