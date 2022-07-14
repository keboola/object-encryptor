<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;
use PHPUnit\Framework\TestCase;
use stdClass;

class ObjectEncryptorTest extends TestCase
{
    private ObjectEncryptorFactory $factory;

    public function setUp(): void
    {
        parent::setUp();
        $this->factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
        $this->factory->setStackId('my-stack');
        $this->factory->setComponentId('dummy-component');
        $this->factory->setConfigurationId('123456');
        $this->factory->setProjectId('123');
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY='. getenv('TEST_AWS_SECRET_ACCESS_KEY'));
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
    }

    public function testEncryptorEmpty(): void
    {
        $factory = new ObjectEncryptorFactory('', '', '');
        $encryptor = $factory->getEncryptor();
        self::expectException(UserException::class);
        self::expectExceptionMessage('Value "secret" is not an encrypted value.');
        $encryptor->decrypt('secret');
    }

    public function testEncryptorScalar(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'secret';
        $encrypted = $encryptor->encrypt($originalText, $encryptor->getRegisteredComponentWrapperClass());
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $encrypted);
        self::assertEquals($originalText, $encryptor->decrypt($encrypted));
    }

    public function cryptoWrapperProvider(): array
    {
        return [
            [
                GenericKMSWrapper::class,
                'KBC::Secure::',
            ],
            [
                GenericAKVWrapper::class,
                'KBC::SecureKV::',
            ],
        ];
    }


    /**
     * @dataProvider cryptoWrapperProvider
     */
    public function testEncryptorStack(string $wrapper, string $prefix): void
    {
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'secret';
        $encrypted = $encryptor->encrypt($originalText, $wrapper);
        self::assertStringStartsWith($prefix, $encrypted);
        self::assertEquals($originalText, $encryptor->decrypt($encrypted));
    }

    public function testEncryptorStackNoCredentials(): void
    {
        putenv('AWS_ACCESS_KEY_ID=');
        putenv('AWS_SECRET_ACCESS_KEY=');
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'secret';
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Encryption failed: Ciphering failed: Failed to obtain encryption key.');
        $encryptor->encrypt($originalText, GenericKMSWrapper::class);
    }

    public function testEncryptorInvalidService(): void
    {
        $encryptor = $this->factory->getEncryptor();
        self::expectExceptionMessage('Invalid crypto wrapper fooBar');
        self::expectException(ApplicationException::class);
        $encryptor->encrypt('secret', 'fooBar');
    }

    public function unsupportedEncryptionInputProvider(): array
    {
        $invalidClass = $this->getMockBuilder(stdClass::class)
            ->disableOriginalConstructor()
            ->getMock();
        return [
            'invalid class' => [
                $invalidClass,
                'Only stdClass, array and string are supported types for encryption.'
            ],
            'invalid class in value' => [
                [
                    'key' => 'value',
                    'key2' => $invalidClass,
                ],
                'Invalid item $key - only stdClass, array and scalar can be encrypted.'
            ],
            'invalid class in encrypted value' => [
                [
                    'key' => 'value',
                    '#key2' => $invalidClass,
                ],
                'Invalid item $key - only stdClass, array and scalar can be encrypted.'
            ],
        ];
    }

    /**
     * @dataProvider unsupportedEncryptionInputProvider
     */
    public function testEncryptorUnsupportedInput($input, string $expectedMessage): void
    {
        $encryptor = $this->factory->getEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->encrypt($input, $encryptor->getRegisteredComponentWrapperClass());
    }

    public function unsupportedDecryptionInputProvider(): array
    {
        $invalidClass = $this->getMockBuilder(stdClass::class)
            ->disableOriginalConstructor()
            ->getMock();
        return [
            'invalid class' => [
                $invalidClass,
                'Only stdClass, array and string are supported types for decryption.'
            ],
            'invalid class in value' => [
                [
                    'key' => 'value',
                    'key2' => $invalidClass,
                ],
                'Invalid item key2 - only stdClass, array and scalar can be decrypted.'
            ],
            'invalid class in encrypted value' => [
                [
                    'key' => 'value',
                    '#key2' => $invalidClass,
                ],
                'Invalid item #key2 - only stdClass, array and scalar can be decrypted.'
            ],
        ];
    }

    /**
     * @dataProvider unsupportedDecryptionInputProvider
     */
    public function testDecryptorUnsupportedInput($input, string $expectedMessage): void
    {
        $encryptor = $this->factory->getEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->decrypt($input);
    }

    public function decryptorInvalidCipherTextProvider(): array
    {
        return [
            'somewhat similar' => [
                'KBC::ComponentSecureKV::eJxLtDK2qs60Mrthis is not a valid cipher but it looks like one lo1Sww=',
                'Value "KBC::ComponentSecureKV::eJxLtDK2qs60Mrthis is not a valid cipher but it looks like one lo1Sww="'
                . ' is not an encrypted value.',
            ],
            'completely off' => [
                'this does not even look like a cipher text',
                'Value "this does not even look like a cipher text" is not an encrypted value.',
            ],
            'somewhat similar in key' => [
                [
                    'key1' => 'somevalue',
                    'key2' => [
                        '#anotherKey' => 'KBC::ComponentSecureKV::eJxLtDK2qs60Mrthis is not a valid cipher but it ' .
                            'looks like one lo1Sww='
                    ]
                ],
                'Invalid cipher text for key #anotherKey Value "KBC::ComponentSecureKV::eJxLtDK2qs60Mrthis is not ' .
                'a valid cipher but it looks like one lo1Sww=" is not an encrypted value.',
            ],
            'completely off in key' => [
                [
                    'key1' => 'somevalue',
                    'key2' => [
                        '#anotherKey' => 'this does not even look like a cipher text'
                    ]
                ],
                'Invalid cipher text for key #anotherKey Value "this does not even look like a cipher text" ' .
                    'is not an encrypted value.',
            ],
        ];
    }

    /**
     * @dataProvider decryptorInvalidCipherTextProvider
     */
    public function testDecryptorInvalidCipherText($encrypted, string $expectedMessage): void
    {
        $encryptor = $this->factory->getEncryptor();
        self::expectException(UserException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->decrypt($encrypted);
    }

    public function testEncryptorAlreadyEncrypted(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt('test', $encryptor->getRegisteredComponentWrapperClass());

        $encrypted = $encryptor->encrypt($encryptedValue, $encryptor->getRegisteredComponentWrapperClass());
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $encrypted);
        self::assertEquals('test', $encryptor->decrypt($encrypted));
    }

    public function testEncryptorAlreadyEncryptedWrapper(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new MockCryptoWrapper();
        $encryptor->pushWrapper($wrapper);

        $secret = 'secret';
        $encryptedValue = $encryptor->encrypt($secret, MockCryptoWrapper::class);
        self::assertEquals('KBC::MockCryptoWrapper==' . $secret, $encryptedValue);

        $encryptedSecond = $encryptor->encrypt($encryptedValue, $encryptor->getRegisteredComponentWrapperClass());
        self::assertEquals('KBC::MockCryptoWrapper==' . $secret, $encryptedSecond);
        self::assertEquals($secret, $encryptor->decrypt($encryptedSecond));
    }

    public function testInvalidWrapper(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new MockCryptoWrapper();
        $encryptor->pushWrapper($wrapper);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('CryptoWrapper prefix KBC::MockCryptoWrapper== is not unique.');
        $encryptor->pushWrapper($wrapper);
    }

    public function testEncryptorSimpleArray(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            'key1' => 'value1',
            '#key2' => 'value2'
        ];
        $result = $encryptor->encrypt($array, $encryptor->getRegisteredComponentWrapperClass());
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $result['#key2']);

        $decrypted = $encryptor->decrypt($result);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['#key2']);
    }

    public function testEncryptorSimpleObject(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new stdClass();
        $object->key1 = 'value1';
        $object->{'#key2'} = 'value2';

        $result = $encryptor->encrypt($object, $encryptor->getRegisteredComponentWrapperClass());
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('#key2', $result);
        self::assertEquals('value1', $result->key1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key2'});

        $decrypted = $encryptor->decrypt($result);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('#key2', $decrypted);
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->{'#key2'});
    }

    public function testEncryptorSimpleArrayScalars(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            'key1' => 'value1',
            '#key2' => 'value2',
            '#key3' => true,
            '#key4' => 1,
            '#key5' => 1.5,
            '#key6' => null,
            'key7' => null
        ];
        $result = $encryptor->encrypt($array, $encryptor->getRegisteredComponentWrapperClass());
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['#key2']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['#key3']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['#key4']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['#key5']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['#key6']);

        $decrypted = $encryptor->decrypt($result);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['#key2']);
        self::assertEquals(true, $decrypted['#key3']);
        self::assertEquals(1, $decrypted['#key4']);
        self::assertEquals(1.5, $decrypted['#key5']);
        self::assertEquals(null, $decrypted['#key6']);
        self::assertEquals(null, $decrypted['key7']);
    }

    public function testEncryptorSimpleObjectScalars(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new stdClass();
        $object->key1= 'value1';
        $object->{'#key2'} = 'value2';
        $object->{'#key3'} = true;
        $object->{'#key4'} = 1;
        $object->{'#key5'} = 1.5;
        $object->{'#key6'} = null;
        $object->key7 = null;

        $result = $encryptor->encrypt($object, $encryptor->getRegisteredComponentWrapperClass());
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('#key2', $result);
        self::assertEquals('value1', $result->key1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key2'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key3'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key4'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key5'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key6'});

        $decrypted = $encryptor->decrypt($result);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('#key2', $decrypted);
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->{'#key2'});
        self::assertEquals(true, $decrypted->{'#key3'});
        self::assertEquals(1, $decrypted->{'#key4'});
        self::assertEquals(1.5, $decrypted->{'#key5'});
        self::assertEquals(null, $decrypted->{'#key6'});
        self::assertEquals(null, $decrypted->{'key7'});
    }

    public function testEncryptorSimpleArrayEncrypted(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt('test', $encryptor->getRegisteredComponentWrapperClass());
        $array = [
            'key1' => 'value1',
            '#key2' => $encryptedValue
        ];
        $result = $encryptor->encrypt($array, $encryptor->getRegisteredComponentWrapperClass());
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals($encryptedValue, $result['#key2']);

        $decrypted = $encryptor->decrypt($result);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('test', $decrypted['#key2']);
    }

    public function testEncryptorSimpleObjectEncrypted(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt('test', $encryptor->getRegisteredComponentWrapperClass());
        $object = new stdClass();
        $object->key1 = 'value1';
        $object->{'#key2'} = $encryptedValue;

        $result = $encryptor->encrypt($object, $encryptor->getRegisteredComponentWrapperClass());
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('#key2', $result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals($encryptedValue, $result->{'#key2'});

        $decrypted = $encryptor->decrypt($result);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('#key2', $decrypted);
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('test', $decrypted->{'#key2'});
    }

    public function testEncryptorNestedArray(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            'key1' => 'value1',
            'key2' => [
                'nestedKey1' => 'value2',
                'nestedKey2' => [
                    '#finalKey' => 'value3'
                ]
            ]
        ];
        $result = $encryptor->encrypt($array, $encryptor->getRegisteredComponentWrapperClass());
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('key2', $result);
        self::assertArrayHasKey('nestedKey1', $result['key2']);
        self::assertArrayHasKey('nestedKey2', $result['key2']);
        self::assertArrayHasKey('#finalKey', $result['key2']['nestedKey2']);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['key2']['nestedKey2']['#finalKey']);

        $decrypted = $encryptor->decrypt($result);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('key2', $decrypted);
        self::assertArrayHasKey('nestedKey1', $decrypted['key2']);
        self::assertArrayHasKey('nestedKey2', $decrypted['key2']);
        self::assertArrayHasKey('#finalKey', $decrypted['key2']['nestedKey2']);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['key2']['nestedKey1']);
        self::assertEquals('value3', $decrypted['key2']['nestedKey2']['#finalKey']);
    }

    public function testEncryptorNestedObject(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new stdClass();
        $nested1 = new stdClass();
        $nested2 = new stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested1->nestedKey1 = 'value2';
        $nested1->nestedKey2 = $nested2;
        $object->key1 = 'value1';
        $object->key2 = $nested1;

        $result = $encryptor->encrypt($object, $encryptor->getRegisteredComponentWrapperClass());
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('key2', $result);
        self::assertObjectHasAttribute('nestedKey1', $result->key2);
        self::assertObjectHasAttribute('nestedKey2', $result->key2);
        self::assertObjectHasAttribute('#finalKey', $result->key2->nestedKey2);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decrypt($result);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('key2', $decrypted);
        self::assertObjectHasAttribute('nestedKey1', $decrypted->key2);
        self::assertObjectHasAttribute('nestedKey2', $decrypted->key2);
        self::assertObjectHasAttribute('#finalKey', $decrypted->key2->nestedKey2);
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->key2->nestedKey1);
        self::assertEquals('value3', $decrypted->key2->nestedKey2->{'#finalKey'});
    }

    public function testEncryptorNestedArrayWithArrayKeyHashmark(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            'key1' => 'value1',
            'key2' => [
                'nestedKey1' => 'value2',
                'nestedKey2' => [
                    '#finalKey' => 'value3'
                ]
            ],
            '#key3' => [
                'anotherNestedKey' => 'someValue',
                '#encryptedNestedKey' => 'someValue2'
            ]
        ];
        $result = $encryptor->encrypt($array, $encryptor->getRegisteredComponentWrapperClass());
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('key2', $result);
        self::assertArrayHasKey('#key3', $result);
        self::assertArrayHasKey('nestedKey1', $result['key2']);
        self::assertArrayHasKey('nestedKey2', $result['key2']);
        self::assertArrayHasKey('#finalKey', $result['key2']['nestedKey2']);
        self::assertArrayHasKey('anotherNestedKey', $result['#key3']);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertEquals('someValue', $result['#key3']['anotherNestedKey']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['#key3']['#encryptedNestedKey']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['key2']['nestedKey2']['#finalKey']);

        $decrypted = $encryptor->decrypt($result);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('key2', $decrypted);
        self::assertArrayHasKey('#key3', $decrypted);
        self::assertArrayHasKey('nestedKey1', $decrypted['key2']);
        self::assertArrayHasKey('nestedKey2', $decrypted['key2']);
        self::assertArrayHasKey('#finalKey', $decrypted['key2']['nestedKey2']);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['key2']['nestedKey1']);
        self::assertEquals('value3', $decrypted['key2']['nestedKey2']['#finalKey']);
        self::assertEquals('someValue', $decrypted['#key3']['anotherNestedKey']);
        self::assertEquals('someValue2', $decrypted['#key3']['#encryptedNestedKey']);
    }

    public function testEncryptorNestedObjectWithArrayKeyHashmark(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new stdClass();
        $nested1 = new stdClass();
        $nested2 = new stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested1->nestedKey1 = 'value2';
        $nested1->nestedKey2 = $nested2;
        $object->key1 = 'value1';
        $object->key2 = $nested1;
        $nested3 = new stdClass();
        $nested3->anotherNestedKey = 'someValue';
        $nested3->{'#encryptedNestedKey'} = 'someValue2';
        $object->{'#key3'} = $nested3;

        $result = $encryptor->encrypt($object, $encryptor->getRegisteredComponentWrapperClass());
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('key2', $result);
        self::assertObjectHasAttribute('#key3', $result);
        self::assertObjectHasAttribute('nestedKey1', $result->key2);
        self::assertObjectHasAttribute('nestedKey2', $result->key2);
        self::assertObjectHasAttribute('#finalKey', $result->key2->nestedKey2);
        self::assertObjectHasAttribute('anotherNestedKey', $result->{'#key3'});
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertEquals('someValue', $result->{'#key3'}->anotherNestedKey);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key3'}->{'#encryptedNestedKey'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decrypt($result);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('key2', $decrypted);
        self::assertObjectHasAttribute('#key3', $decrypted);
        self::assertObjectHasAttribute('nestedKey1', $decrypted->key2);
        self::assertObjectHasAttribute('nestedKey2', $decrypted->key2);
        self::assertObjectHasAttribute('#finalKey', $decrypted->key2->nestedKey2);
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->key2->nestedKey1);
        self::assertEquals('value3', $decrypted->key2->nestedKey2->{'#finalKey'});
        self::assertEquals('someValue', $decrypted->{'#key3'}->anotherNestedKey);
        self::assertEquals('someValue2', $decrypted->{'#key3'}->{'#encryptedNestedKey'});
    }

    public function testEncryptorNestedArrayEncrypted(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt('test', $encryptor->getRegisteredComponentWrapperClass());
        $array = [
            'key1' => 'value1',
            'key2' => [
                'nestedKey1' => 'value2',
                'nestedKey2' => [
                    '#finalKey' => 'value3',
                    '#finalKeyEncrypted' => $encryptedValue
                ]
            ]
        ];

        $result = $encryptor->encrypt($array, $encryptor->getRegisteredComponentWrapperClass());
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('key2', $result);
        self::assertArrayHasKey('nestedKey1', $result['key2']);
        self::assertArrayHasKey('nestedKey2', $result['key2']);
        self::assertArrayHasKey('#finalKey', $result['key2']['nestedKey2']);
        self::assertArrayHasKey('#finalKeyEncrypted', $result['key2']['nestedKey2']);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['key2']['nestedKey2']['#finalKey']);
        self::assertEquals($encryptedValue, $result['key2']['nestedKey2']['#finalKeyEncrypted']);

        $decrypted = $encryptor->decrypt($result);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('key2', $decrypted);
        self::assertArrayHasKey('nestedKey1', $decrypted['key2']);
        self::assertArrayHasKey('nestedKey2', $decrypted['key2']);
        self::assertArrayHasKey('#finalKey', $decrypted['key2']['nestedKey2']);
        self::assertArrayHasKey('#finalKeyEncrypted', $decrypted['key2']['nestedKey2']);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['key2']['nestedKey1']);
        self::assertEquals('value3', $decrypted['key2']['nestedKey2']['#finalKey']);
        self::assertEquals('test', $decrypted['key2']['nestedKey2']['#finalKeyEncrypted']);
    }

    public function testEncryptorNestedObjectEncrypted(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt('test', $encryptor->getRegisteredComponentWrapperClass());

        $object = new stdClass();
        $object->key1 = 'value1';
        $nested1 = new stdClass();
        $nested1->nestedKey1 = 'value2';
        $nested2 = new stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested2->{'#finalKeyEncrypted'} = $encryptedValue;
        $nested1->nestedKey2 = $nested2;
        $object->key2 = $nested1;

        $result = $encryptor->encrypt($object, $encryptor->getRegisteredComponentWrapperClass());
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('key2', $result);
        self::assertObjectHasAttribute('nestedKey1', $result->key2);
        self::assertObjectHasAttribute('nestedKey2', $result->key2);
        self::assertObjectHasAttribute('#finalKey', $result->key2->nestedKey2);
        self::assertObjectHasAttribute('#finalKeyEncrypted', $result->key2->nestedKey2);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2->nestedKey2->{'#finalKey'});
        self::assertEquals($encryptedValue, $result->key2->nestedKey2->{'#finalKeyEncrypted'});

        $decrypted = $encryptor->decrypt($result);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('key2', $decrypted);
        self::assertObjectHasAttribute('nestedKey1', $decrypted->key2);
        self::assertObjectHasAttribute('nestedKey2', $decrypted->key2);
        self::assertObjectHasAttribute('#finalKey', $decrypted->key2->nestedKey2);
        self::assertObjectHasAttribute('#finalKeyEncrypted', $decrypted->key2->nestedKey2);
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->key2->nestedKey1);
        self::assertEquals('value3', $decrypted->key2->nestedKey2->{'#finalKey'});
        self::assertEquals('test', $decrypted->key2->nestedKey2->{'#finalKeyEncrypted'});
    }

    public function testEncryptorNestedArrayWithArray(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            'key1' => 'value1',
            'key2' => [
                ['nestedKey1' => 'value2'],
                ['nestedKey2' => ['#finalKey' => 'value3']]
            ]
        ];
        $result = $encryptor->encrypt($array, $encryptor->getRegisteredComponentWrapperClass());
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('key2', $result);
        self::assertCount(2, $result['key2']);
        self::assertArrayHasKey('nestedKey1', $result['key2'][0]);
        self::assertArrayHasKey('nestedKey2', $result['key2'][1]);
        self::assertArrayHasKey('#finalKey', $result['key2'][1]['nestedKey2']);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2'][0]['nestedKey1']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['key2'][1]['nestedKey2']['#finalKey']);

        $decrypted = $encryptor->decrypt($result);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('key2', $decrypted);
        self::assertCount(2, $result['key2']);
        self::assertArrayHasKey('nestedKey1', $decrypted['key2'][0]);
        self::assertArrayHasKey('nestedKey2', $decrypted['key2'][1]);
        self::assertArrayHasKey('#finalKey', $decrypted['key2'][1]['nestedKey2']);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['key2'][0]['nestedKey1']);
        self::assertEquals('value3', $decrypted['key2'][1]['nestedKey2']['#finalKey']);
    }

    public function testEncryptorNestedObjectWithArray(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new stdClass();
        $object->key1 = 'value1';
        $object->key2 = [];
        $nested1 = new stdClass();
        $nested1->nestedKey1 = 'value2';
        $object->key2[] = $nested1;
        $nested2 = new stdClass();
        $nested3 = new stdClass();
        $nested3->{'#finalKey'} = 'value3';
        $nested2->nestedKey2 = $nested3;
        $object->key2[] = $nested2;

        $result = $encryptor->encrypt($object, $encryptor->getRegisteredComponentWrapperClass());

        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('key2', $result);
        self::assertCount(2, $result->key2);
        self::assertObjectHasAttribute('nestedKey1', $result->key2[0]);
        self::assertObjectHasAttribute('nestedKey2', $result->key2[1]);
        self::assertObjectHasAttribute('#finalKey', $result->key2[1]->nestedKey2);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2[0]->nestedKey1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2[1]->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decrypt($result);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('key2', $decrypted);
        self::assertCount(2, $result->key2);
        self::assertObjectHasAttribute('nestedKey1', $decrypted->key2[0]);
        self::assertObjectHasAttribute('nestedKey2', $decrypted->key2[1]);
        self::assertObjectHasAttribute('#finalKey', $decrypted->key2[1]->nestedKey2);
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->key2[0]->nestedKey1);
        self::assertEquals('value3', $decrypted->key2[1]->nestedKey2->{'#finalKey'});
    }

    public function testMixedCryptoWrappersDecryptArray(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            '#key1' => $encryptor->encrypt('value1', $encryptor->getRegisteredComponentWrapperClass()),
            '#key2' => $encryptor->encrypt('value2', $encryptor->getRegisteredProjectWrapperClass())
        ];
        self::assertStringStartsWith('KBC::ComponentSecure', $array['#key1']);
        self::assertStringStartsWith('KBC::ProjectSecureKV::', $array['#key2']);

        $decrypted = $encryptor->decrypt($array);
        self::assertArrayHasKey('#key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertCount(2, $decrypted);
        self::assertEquals('value1', $decrypted['#key1']);
        self::assertEquals('value2', $decrypted['#key2']);
    }

    public function testMixedCryptoWrappersDecryptObject(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new stdClass();
        $object->{'#key1'} = $encryptor->encrypt('value1', $encryptor->getRegisteredComponentWrapperClass());
        $object->{'#key2'} = $encryptor->encrypt('value2', $encryptor->getRegisteredProjectWrapperClass());

        self::assertStringStartsWith('KBC::ComponentSecureKV::', $object->{'#key1'});
        self::assertStringStartsWith('KBC::ProjectSecureKV::', $object->{'#key2'});

        $decrypted = $encryptor->decrypt($object);
        self::assertObjectHasAttribute('#key1', $decrypted);
        self::assertObjectHasAttribute('#key2', $decrypted);
        self::assertEquals('value1', $decrypted->{'#key1'});
        self::assertEquals('value2', $decrypted->{'#key2'});
    }

    public function testEncryptEmptyArray(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [];
        $encrypted = $encryptor->encrypt($array, $encryptor->getRegisteredComponentWrapperClass());
        self::assertEquals([], $encrypted);
        self::assertEquals([], $encryptor->decrypt($encrypted));
    }

    public function testEncryptEmptyObject(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new stdClass();
        $encrypted = $encryptor->encrypt($object, $encryptor->getRegisteredComponentWrapperClass());
        self::assertEquals(stdClass::class, get_class($encrypted));
        self::assertEquals(stdClass::class, get_class($encryptor->decrypt($encrypted)));
    }

    public function testEncryptorNoWrappers(): void
    {
        $encryptor = new ObjectEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No Component wrappers registered.');
        $encryptor->encrypt('test', $encryptor->getRegisteredComponentWrapperClass());
    }

    public function testEncryptorDecodedJSONObject(): void
    {
        $encryptor = $this->factory->getEncryptor();
        $json = '{
            "key1": "value1",
            "key2": {
                "nestedKey1": "value2",
                "nestedKey2": {
                    "#finalKey": "value3"
                }
            },
            "#key3": {
                "anotherNestedKey": "someValue",
                "#encryptedNestedKey": "someValue2"
            },
            "array": ["a", "b"],
            "emptyArray": [],
            "emptyObject": {}
        }';

        $result = $encryptor->encrypt(json_decode($json), $encryptor->getRegisteredComponentWrapperClass());
        self::assertTrue(is_object($result));
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('key2', $result);
        self::assertObjectHasAttribute('#key3', $result);
        self::assertObjectHasAttribute('array', $result);
        self::assertObjectHasAttribute('emptyArray', $result);
        self::assertObjectHasAttribute('emptyObject', $result);
        self::assertObjectHasAttribute('nestedKey1', $result->key2);
        self::assertObjectHasAttribute('nestedKey2', $result->key2);
        self::assertObjectHasAttribute('#finalKey', $result->key2->nestedKey2);
        self::assertTrue(is_array($result->array));
        self::assertTrue(is_array($result->emptyArray));
        self::assertTrue(is_object($result->emptyObject));
        self::assertTrue(is_object($result->key2));
        self::assertObjectHasAttribute('anotherNestedKey', $result->{'#key3'});
        self::assertTrue(is_object($result->{'#key3'}));
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertEquals('someValue', $result->{'#key3'}->anotherNestedKey);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $result->{'#key3'}->{'#encryptedNestedKey'});
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $result->key2->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decrypt($result);
        self::assertTrue(is_object($decrypted));
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('key2', $decrypted);
        self::assertObjectHasAttribute('#key3', $decrypted);
        self::assertObjectHasAttribute('array', $decrypted);
        self::assertObjectHasAttribute('emptyArray', $decrypted);
        self::assertObjectHasAttribute('emptyObject', $decrypted);
        self::assertObjectHasAttribute('nestedKey1', $decrypted->key2);
        self::assertObjectHasAttribute('nestedKey2', $decrypted->key2);
        self::assertObjectHasAttribute('#finalKey', $decrypted->key2->nestedKey2);
        self::assertTrue(is_array($decrypted->array));
        self::assertTrue(is_array($decrypted->emptyArray));
        self::assertTrue(is_object($decrypted->emptyObject));
        self::assertTrue(is_object($decrypted->key2));
        self::assertObjectHasAttribute('anotherNestedKey', $decrypted->{'#key3'});
        self::assertTrue(is_object($decrypted->{'#key3'}));
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->key2->nestedKey1);
        self::assertEquals('someValue', $decrypted->{'#key3'}->anotherNestedKey);
        self::assertEquals('someValue2', $decrypted->{'#key3'}->{'#encryptedNestedKey'});
        self::assertEquals('value3', $decrypted->key2->nestedKey2->{'#finalKey'});

        self::assertEquals(json_encode($decrypted), json_encode(json_decode($json)));
    }

    /**
     * @dataProvider registeredProvider()
     */
    public function testGetRegisteredWrapperEncryptor(string $kmsKey, string $keyVaultUrl, string $classifier, string $expectedClass): void
    {
        $factory = new ObjectEncryptorFactory($kmsKey, getenv('TEST_AWS_REGION'), $keyVaultUrl);
        $factory->setStackId('my-stack');
        $factory->setComponentId('dummy-component');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $encryptor = $factory->getEncryptor();
        $method = 'getRegistered' . $classifier . 'WrapperClass';
        self::assertEquals($expectedClass, $encryptor->$method());
    }

    public function registeredProvider(): array
    {
        return [
            'kms-akv-component' => [
                getenv('TEST_AWS_KMS_KEY_ID'),
                getenv('TEST_KEY_VAULT_URL'),
                'Component',
                ComponentAKVWrapper::class,
            ],
            'kms-akv-project' => [
                getenv('TEST_AWS_KMS_KEY_ID'),
                getenv('TEST_KEY_VAULT_URL'),
                'Project',
                ProjectAKVWrapper::class,
            ],
            'kms-akv-configuration' => [
                getenv('TEST_AWS_KMS_KEY_ID'),
                getenv('TEST_KEY_VAULT_URL'),
                'Configuration',
                ConfigurationAKVWrapper::class,
            ],
            'kms-component' => [
                getenv('TEST_AWS_KMS_KEY_ID'),
                '',
                'Component',
                ComponentKMSWrapper::class,
            ],
            'kms-project' => [
                getenv('TEST_AWS_KMS_KEY_ID'),
                '',
                'Project',
                ProjectKMSWrapper::class,
            ],
            'kms-configuration' => [
                getenv('TEST_AWS_KMS_KEY_ID'),
                '',
                'Configuration',
                ConfigurationKMSWrapper::class,
            ],
            'akv-component' => [
                '',
                getenv('TEST_KEY_VAULT_URL'),
                'Component',
                ComponentAKVWrapper::class,
            ],
            'akv-project' => [
                '',
                getenv('TEST_KEY_VAULT_URL'),
                'Project',
                ProjectAKVWrapper::class,
            ],
            'akv-configuration' => [
                '',
                getenv('TEST_KEY_VAULT_URL'),
                'Configuration',
                ConfigurationAKVWrapper::class,
            ],
        ];
    }

    /**
     * @dataProvider registeredFailureProvider()
     */
    public function testGetRegisteredWrapperFailure(string $classifier, string $expectedMessage): void
    {
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
        $factory->setStackId('my-stack');
        $encryptor = $factory->getEncryptor();
        $method = 'getRegistered' . $classifier . 'WrapperClass';
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->$method();
    }

    public function registeredFailureProvider(): array
    {
        return [
            [
                'Component',
                'No Component wrappers registered.',
            ],
            [
                'Project',
                'No Project wrappers registered.',
            ],
            [
                'Configuration',
                'No Configuration wrappers registered.',
            ],
        ];
    }
}
