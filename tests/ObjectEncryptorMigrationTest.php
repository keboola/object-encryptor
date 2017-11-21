<?php

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Legacy\Encryptor;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use Keboola\ObjectEncryptor\Wrapper\StackWrapper;
use PHPUnit\Framework\TestCase;

class ObjectEncryptorMigrationTest extends TestCase
{
    /**
     * @var ObjectEncryptorFactory
     */
    private $factory;

    /**
     * @var string
     */
    private $aesKey;

    public function setUp()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $this->aesKey = '123456789012345678901234567890ab';
        $stack = 'us-east-1';
        $this->factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $this->aesKey, $stackKey, $stack);
        $this->factory->setComponentId('keboola.docker-demo');
        $this->factory->setConfigurationId('123456');
        $this->factory->setProjectId('123');
    }

    public function testEncryptorScalar()
    {
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'secret';
        $encrypted = $encryptor->encrypt($originalText);
        self::assertStringStartsWith("KBC::Encrypted==", $encrypted);
        self::assertEquals($originalText, $encryptor->decrypt($encrypted));
        $migrated = $encryptor->migrate($encrypted, StackWrapper::class);
        self::assertStringStartsWith("KBC::SecureV3::CPF::", $migrated);
        self::assertEquals($originalText, $encryptor->decrypt($migrated));
    }

    public function testEncryptorStack()
    {
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'secret';
        $encrypted = $encryptor->encrypt($originalText, StackWrapper::class);
        self::assertStringStartsWith("KBC::SecureV3::CPF::", $encrypted);
        self::assertEquals($originalText, $encryptor->decrypt($encrypted));
        $migrated = $encryptor->migrate($encrypted, StackWrapper::class);
        self::assertStringStartsWith("KBC::SecureV3::CPF::", $migrated);
        self::assertEquals($originalText, $encryptor->decrypt($migrated));
    }

    public function testEncryptorNestedArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            "key1" => "value1",
            "key2" => [
                "nestedKey1" => "value2",
                "nestedKey2" => [
                    "#finalKey" => "value3"
                ]
            ]
        ];
        $result = $encryptor->encrypt($array);
        self::assertEquals("value1", $result["key1"]);
        self::assertEquals("value2", $result["key2"]["nestedKey1"]);
        self::assertStringStartsWith("KBC::Encrypted==", $result["key2"]["nestedKey2"]["#finalKey"]);

        $decrypted = $encryptor->decrypt($result);
        self::assertEquals("value1", $decrypted["key1"]);
        self::assertEquals("value2", $decrypted["key2"]["nestedKey1"]);
        self::assertEquals("value3", $decrypted["key2"]["nestedKey2"]["#finalKey"]);

        $migrated = $encryptor->migrate($result, StackWrapper::class);
        self::assertStringStartsWith("KBC::SecureV3::CPF::", $migrated["key2"]["nestedKey2"]["#finalKey"]);
        $decrypted = $encryptor->decrypt($migrated);
        self::assertEquals("value1", $decrypted["key1"]);
        self::assertEquals("value2", $decrypted["key2"]["nestedKey1"]);
        self::assertEquals("value3", $decrypted["key2"]["nestedKey2"]["#finalKey"]);
    }

    public function testMixedCryptoWrappersDecryptArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new AnotherCryptoWrapper();
        $wrapper->setKey(md5(uniqid()));
        $encryptor->pushWrapper($wrapper);

        $array = [
            "#key1" => $encryptor->encrypt("value1"),
            "#key2" => $encryptor->encrypt("value2", AnotherCryptoWrapper::class)
        ];
        self::assertStringStartsWith("KBC::Encrypted==", $array["#key1"]);
        self::assertStringStartsWith("KBC::AnotherCryptoWrapper==", $array["#key2"]);
        $decrypted = $encryptor->decrypt($array);
        self::assertEquals("value1", $decrypted["#key1"]);
        self::assertEquals("value2", $decrypted["#key2"]);
        $migrated = $encryptor->migrate($array, StackWrapper::class);

        self::assertStringStartsWith("KBC::SecureV3::CPF::", $migrated["#key1"]);
        self::assertStringStartsWith("KBC::SecureV3::CPF::", $migrated["#key2"]);
        $decrypted = $encryptor->decrypt($migrated);
        self::assertEquals("value1", $decrypted["#key1"]);
        self::assertEquals("value2", $decrypted["#key2"]);
    }
}
