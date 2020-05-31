<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Legacy\Encryptor;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use PHPUnit\Framework\TestCase;

class ObjectEncryptorTest extends TestCase
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
        parent::setUp();
        $legacyKey = '1234567890123456';
        $this->aesKey = '123456789012345678901234567890ab';
        $this->factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $this->aesKey, getenv('TEST_KEY_VAULT_URL'));
        $this->factory->setStackId('my-stack');
        $this->factory->setComponentId('dummy-component');
        $this->factory->setConfigurationId('123456');
        $this->factory->setProjectId('123');
        putenv('AWS_ACCESS_KEY_ID=' . AWS_ACCESS_KEY_ID);
        putenv('AWS_SECRET_ACCESS_KEY='. AWS_SECRET_ACCESS_KEY);
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
    }

    public function testEncryptorEmpty()
    {
        $factory = new ObjectEncryptorFactory('', '', '', '', '');
        $encryptor = $factory->getEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('There are no wrappers registered for the encryptor.');
        $encrypted = $encryptor->decrypt('secret');
    }

    public function testEncryptorScalar()
    {
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'secret';
        $encrypted = $encryptor->encrypt($originalText);
        self::assertStringStartsWith('KBC::Encrypted==', $encrypted);
        self::assertEquals($originalText, $encryptor->decrypt($encrypted));
    }


    public function cryptoWrapperProvider()
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
     * @param string $wrapper
     * @param $prefix
     * @throws ApplicationException
     * @throws UserException
     * @dataProvider cryptoWrapperProvider
     */
    public function testEncryptorStack($wrapper, $prefix)
    {
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'secret';
        $encrypted = $encryptor->encrypt($originalText, $wrapper);
        self::assertStringStartsWith($prefix, $encrypted);
        self::assertEquals($originalText, $encryptor->decrypt($encrypted));
    }

    public function testEncryptorStackNoCredentials()
    {
        putenv('AWS_ACCESS_KEY_ID=');
        putenv('AWS_SECRET_ACCESS_KEY=');
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'secret';
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Encryption failed: Ciphering failed: Failed to obtain encryption key.');
        $encryptor->encrypt($originalText, GenericKMSWrapper::class);
    }

    public function testEncryptorInvalidService()
    {
        $encryptor = $this->factory->getEncryptor();
        self::expectExceptionMessage('Invalid crypto wrapper fooBar');
        self::expectException(ApplicationException::class);
        $encryptor->encrypt('secret', 'fooBar');
    }

    public function unsupportedEncryptionInputProvider()
    {
        $invalidClass = $this->getMockBuilder(\stdClass::class)
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
     * @param mixed $input
     * @param string $expectedMessage
     * @throws ApplicationException
     */
    public function testEncryptorUnsupportedInput($input, $expectedMessage)
    {
        $encryptor = $this->factory->getEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->encrypt($input);
    }

    public function unsupportedDecryptionInputProvider()
    {
        $invalidClass = $this->getMockBuilder(\stdClass::class)
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
     * @param mixed $input
     * @param string $expectedMessage
     * @throws ApplicationException
     */
    public function testDecryptorUnsupportedInput($input, $expectedMessage)
    {
        $encryptor = $this->factory->getEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->decrypt($input);
    }

    public function decryptorInvalidCipherTextProvider()
    {
        return [
            'somewhat similar' => [
                'KBC::Encrypted==yI0sawothis is not a valid cipher but it looks like one N2Jg==',
                'Value KBC::Encrypted==yI0sawothis is not a valid cipher but it looks like one N2Jg== is not an encrypted value.',
            ],
            'completely off' => [
                'this does not even look like a cipher text',
                'Value is not an encrypted value.',
            ],
            'somewhat similar in key' => [
                [
                    'key1' => 'somevalue',
                    'key2' => [
                        '#anotherKey' => 'KBC::Encrypted==yI0sawothis is not a valid cipher but it looks like one N2Jg=='
                    ]
                ],
                'Invalid cipher text for key #anotherKey Value KBC::Encrypted==yI0sawothis is not a valid cipher but it looks like one N2Jg== is not an encrypted value.',
            ],
            'completely off in key' => [
                [
                    'key1' => 'somevalue',
                    'key2' => [
                        '#anotherKey' => 'this does not even look like a cipher text'
                    ]
                ],
                'Invalid cipher text for key #anotherKey Value is not an encrypted value.',
            ],
        ];
    }

    /**
     * @dataProvider decryptorInvalidCipherTextProvider
     * @param string $encrypted
     * @param string $expectedMessage
     * @throws ApplicationException
     * @throws UserException
     */
    public function testDecryptorInvalidCipherText($encrypted, $expectedMessage)
    {
        $encryptor = $this->factory->getEncryptor();
        self::expectException(UserException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->decrypt($encrypted);
    }

    public function testEncryptorAlreadyEncrypted()
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt('test');

        $encrypted = $encryptor->encrypt($encryptedValue);
        self::assertEquals('KBC::Encrypted==', substr($encrypted, 0, 16));
        self::assertEquals('test', $encryptor->decrypt($encrypted));
    }

    public function testEncryptorAlreadyEncryptedWrapper()
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new MockCryptoWrapper();
        $encryptor->pushWrapper($wrapper);

        $secret = 'secret';
        $encryptedValue = $encryptor->encrypt($secret, MockCryptoWrapper::class);
        self::assertEquals('KBC::MockCryptoWrapper==' . $secret, $encryptedValue);

        $encryptedSecond = $encryptor->encrypt($encryptedValue);
        self::assertEquals('KBC::MockCryptoWrapper==' . $secret, $encryptedSecond);
        self::assertEquals($secret, $encryptor->decrypt($encryptedSecond));
    }

    public function testInvalidWrapper()
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new MockCryptoWrapper();
        $encryptor->pushWrapper($wrapper);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('CryptoWrapper prefix KBC::MockCryptoWrapper== is not unique.');
        $encryptor->pushWrapper($wrapper);
    }

    public function testEncryptorSimpleArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            'key1' => 'value1',
            '#key2' => 'value2'
        ];
        $result = $encryptor->encrypt($array);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('KBC::Encrypted==', substr($result['#key2'], 0, 16));

        $decrypted = $encryptor->decrypt($result);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['#key2']);
    }

    public function testEncryptorSimpleObject()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $object->key1 = 'value1';
        $object->{'#key2'} = 'value2';

        $result = $encryptor->encrypt($object);
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('#key2', $result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('KBC::Encrypted==', substr($result->{'#key2'}, 0, 16));

        $decrypted = $encryptor->decrypt($result);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('#key2', $decrypted);
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->{'#key2'});
    }

    public function testEncryptorSimpleArrayScalars()
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
        $result = $encryptor->encrypt($array);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('KBC::Encrypted==', substr($result['#key2'], 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result['#key3'], 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result['#key4'], 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result['#key5'], 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result['#key6'], 0, 16));

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

    public function testEncryptorSimpleObjectScalars()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $object->key1= 'value1';
        $object->{'#key2'} = 'value2';
        $object->{'#key3'} = true;
        $object->{'#key4'} = 1;
        $object->{'#key5'} = 1.5;
        $object->{'#key6'} = null;
        $object->key7 = null;

        $result = $encryptor->encrypt($object);
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('#key2', $result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('KBC::Encrypted==', substr($result->{'#key2'}, 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result->{'#key3'}, 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result->{'#key4'}, 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result->{'#key5'}, 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result->{'#key6'}, 0, 16));

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

    public function testEncryptorSimpleArrayEncrypted()
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt('test');
        $array = [
            'key1' => 'value1',
            '#key2' => $encryptedValue
        ];
        $result = $encryptor->encrypt($array);
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

    public function testEncryptorSimpleObjectEncrypted()
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt('test');
        $object = new \stdClass();
        $object->key1 = 'value1';
        $object->{'#key2'} = $encryptedValue;

        $result = $encryptor->encrypt($object);
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

    public function testEncryptorNestedArray()
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
        $result = $encryptor->encrypt($array);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('key2', $result);
        self::assertArrayHasKey('nestedKey1', $result['key2']);
        self::assertArrayHasKey('nestedKey2', $result['key2']);
        self::assertArrayHasKey('#finalKey', $result['key2']['nestedKey2']);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertEquals('KBC::Encrypted==', substr($result['key2']['nestedKey2']['#finalKey'], 0, 16));

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

    public function testEncryptorNestedObject()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $nested1 = new \stdClass();
        $nested2 = new \stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested1->nestedKey1 = 'value2';
        $nested1->nestedKey2 = $nested2;
        $object->key1 = 'value1';
        $object->key2 = $nested1;

        $result = $encryptor->encrypt($object);
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('key2', $result);
        self::assertObjectHasAttribute('nestedKey1', $result->key2);
        self::assertObjectHasAttribute('nestedKey2', $result->key2);
        self::assertObjectHasAttribute('#finalKey', $result->key2->nestedKey2);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertEquals('KBC::Encrypted==', substr($result->key2->nestedKey2->{'#finalKey'}, 0, 16));

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

    public function testEncryptorNestedArrayWithArrayKeyHashmark()
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
        $result = $encryptor->encrypt($array);
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
        self::assertEquals('KBC::Encrypted==', substr($result['#key3']['#encryptedNestedKey'], 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result['key2']['nestedKey2']['#finalKey'], 0, 16));

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

    public function testEncryptorNestedObjectWithArrayKeyHashmark()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $nested1 = new \stdClass();
        $nested2 = new \stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested1->nestedKey1 = 'value2';
        $nested1->nestedKey2 = $nested2;
        $object->key1 = 'value1';
        $object->key2 = $nested1;
        $nested3 = new \stdClass();
        $nested3->anotherNestedKey = 'someValue';
        $nested3->{'#encryptedNestedKey'} = 'someValue2';
        $object->{'#key3'} = $nested3;

        $result = $encryptor->encrypt($object);
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
        self::assertEquals('KBC::Encrypted==', substr($result->{'#key3'}->{'#encryptedNestedKey'}, 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result->key2->nestedKey2->{'#finalKey'}, 0, 16));

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

    public function testEncryptorNestedArrayEncrypted()
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt('test');
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

        $result = $encryptor->encrypt($array);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('key2', $result);
        self::assertArrayHasKey('nestedKey1', $result['key2']);
        self::assertArrayHasKey('nestedKey2', $result['key2']);
        self::assertArrayHasKey('#finalKey', $result['key2']['nestedKey2']);
        self::assertArrayHasKey('#finalKeyEncrypted', $result['key2']['nestedKey2']);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertEquals('KBC::Encrypted==', substr($result['key2']['nestedKey2']['#finalKey'], 0, 16));
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

    public function testEncryptorNestedObjectEncrypted()
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt('test');

        $object = new \stdClass();
        $object->key1 = 'value1';
        $nested1 = new \stdClass();
        $nested1->nestedKey1 = 'value2';
        $nested2 = new \stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested2->{'#finalKeyEncrypted'} = $encryptedValue;
        $nested1->nestedKey2 = $nested2;
        $object->key2 = $nested1;

        $result = $encryptor->encrypt($object);
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('key2', $result);
        self::assertObjectHasAttribute('nestedKey1', $result->key2);
        self::assertObjectHasAttribute('nestedKey2', $result->key2);
        self::assertObjectHasAttribute('#finalKey', $result->key2->nestedKey2);
        self::assertObjectHasAttribute('#finalKeyEncrypted', $result->key2->nestedKey2);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertEquals('KBC::Encrypted==', substr($result->key2->nestedKey2->{'#finalKey'}, 0, 16));
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

    public function testEncryptorNestedArrayWithArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            'key1' => 'value1',
            'key2' => [
                ['nestedKey1' => 'value2'],
                ['nestedKey2' => ['#finalKey' => 'value3']]
            ]
        ];
        $result = $encryptor->encrypt($array);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('key2', $result);
        self::assertCount(2, $result['key2']);
        self::assertArrayHasKey('nestedKey1', $result['key2'][0]);
        self::assertArrayHasKey('nestedKey2', $result['key2'][1]);
        self::assertArrayHasKey('#finalKey', $result['key2'][1]['nestedKey2']);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2'][0]['nestedKey1']);
        self::assertEquals('KBC::Encrypted==', substr($result['key2'][1]['nestedKey2']['#finalKey'], 0, 16));

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

    public function testEncryptorNestedObjectWithArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $object->key1 = 'value1';
        $object->key2 = [];
        $nested1 = new \stdClass();
        $nested1->nestedKey1 = 'value2';
        $object->key2[] = $nested1;
        $nested2 = new \stdClass();
        $nested3 = new \stdClass();
        $nested3->{'#finalKey'} = 'value3';
        $nested2->nestedKey2 = $nested3;
        $object->key2[] = $nested2;

        $result = $encryptor->encrypt($object);

        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('key2', $result);
        self::assertCount(2, $result->key2);
        self::assertObjectHasAttribute('nestedKey1', $result->key2[0]);
        self::assertObjectHasAttribute('nestedKey2', $result->key2[1]);
        self::assertObjectHasAttribute('#finalKey', $result->key2[1]->nestedKey2);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2[0]->nestedKey1);
        self::assertEquals('KBC::Encrypted==', substr($result->key2[1]->nestedKey2->{'#finalKey'}, 0, 16));

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

    public function testMixedCryptoWrappersDecryptArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new AnotherCryptoWrapper();
        $wrapper->setKey(md5(uniqid()));
        $encryptor->pushWrapper($wrapper);

        $array = [
            '#key1' => $encryptor->encrypt('value1'),
            '#key2' => $encryptor->encrypt('value2', AnotherCryptoWrapper::class)
        ];
        self::assertEquals('KBC::Encrypted==', substr($array['#key1'], 0, 16));
        self::assertEquals('KBC::AnotherCryptoWrapper==', substr($array['#key2'], 0, 27));

        $decrypted = $encryptor->decrypt($array);
        self::assertArrayHasKey('#key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertCount(2, $decrypted);
        self::assertEquals('value1', $decrypted['#key1']);
        self::assertEquals('value2', $decrypted['#key2']);
    }

    public function testMixedCryptoWrappersDecryptObject()
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new AnotherCryptoWrapper();
        $wrapper->setKey(md5(uniqid()));
        $encryptor->pushWrapper($wrapper);

        $object = new \stdClass();
        $object->{'#key1'} = $encryptor->encrypt('value1');
        $object->{'#key2'} = $encryptor->encrypt('value2', AnotherCryptoWrapper::class);

        self::assertEquals('KBC::Encrypted==', substr($object->{'#key1'}, 0, 16));
        self::assertEquals('KBC::AnotherCryptoWrapper==', substr($object->{'#key2'}, 0, 27));

        $decrypted = $encryptor->decrypt($object);
        self::assertObjectHasAttribute('#key1', $decrypted);
        self::assertObjectHasAttribute('#key2', $decrypted);
        self::assertEquals('value1', $decrypted->{'#key1'});
        self::assertEquals('value2', $decrypted->{'#key2'});
    }

    public function testEncryptEmptyArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [];
        $encrypted = $encryptor->encrypt($array);
        self::assertEquals([], $encrypted);
        self::assertEquals([], $encryptor->decrypt($encrypted));
    }

    public function testEncryptEmptyObject()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $encrypted = $encryptor->encrypt($object);
        self::assertEquals(\stdClass::class, get_class($encrypted));
        self::assertEquals(\stdClass::class, get_class($encryptor->decrypt($encrypted)));
    }

    public function testEncryptorNoWrappers()
    {
        $encryptor = new ObjectEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid crypto wrapper Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper');
        $encryptor->encrypt('test');
    }

    public function testEncryptorDecodedJSONObject()
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

        $result = $encryptor->encrypt(json_decode($json));
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
        self::assertEquals('KBC::Encrypted==', substr($result->{'#key3'}->{'#encryptedNestedKey'}, 0, 16));
        self::assertEquals('KBC::Encrypted==', substr($result->key2->nestedKey2->{'#finalKey'}, 0, 16));

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

    public function testEncryptorLegacyNoMCrypt()
    {
        $encryptor = $this->factory->getEncryptor(true);
        $prop = new \ReflectionProperty($encryptor, 'legacyEncryptor');
        $prop->setAccessible(true);
        $legacyEncryptor = $prop->getValue($encryptor);
        if (!function_exists('mcrypt_module_open')) {
            self::assertNull($legacyEncryptor);
        } else {
            self::assertNotNull($legacyEncryptor);
        }
    }

    public function testEncryptorLegacyNoMCryptNoRequire()
    {
        $encryptor = $this->factory->getEncryptor();
        $prop = new \ReflectionProperty($encryptor, 'legacyEncryptor');
        $prop->setAccessible(true);
        $legacyEncryptor = $prop->getValue($encryptor);
        self::assertNull($legacyEncryptor);
    }

    public function testEncryptorLegacy()
    {
        if (!function_exists('mcrypt_module_open')) {
            self::markTestSkipped("Mcrypt not available");
        }
        $encryptor = $this->factory->getEncryptor(true);
        $legacyEncryptor = new Encryptor($this->aesKey);

        $originalText = 'secret';
        $encrypted = $legacyEncryptor->encrypt($originalText);
        self::assertNotEquals($originalText, $encrypted);
        self::assertEquals($originalText, $encryptor->decrypt($encrypted));
    }

    public function testEncryptorLegacyFail()
    {
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'test';
        self::expectException(UserException::class);
        self::expectExceptionMessage('Value is not an encrypted value.');
        $encryptor->decrypt($originalText);
    }
}
