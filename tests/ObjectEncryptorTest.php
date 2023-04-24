<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Generator;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use stdClass;

class ObjectEncryptorTest extends AbstractTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY=' . getenv('TEST_AWS_SECRET_ACCESS_KEY'));
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
    }

    private function getEncryptor(): ObjectEncryptor
    {
        $options = new EncryptorOptions(
            'my-stack',
            self::getKmsKeyId(),
            self::getKmsRegion(),
            null,
            self::getAkvUrl()
        );
        $factory = new ObjectEncryptorFactory();
        return $factory->getEncryptor($options);
    }

    public function testEncryptorScalar(): void
    {
        $encryptor = $this->getEncryptor();
        $originalText = 'secret';
        $encrypted = $encryptor->encryptForComponent($originalText, 'my-component');
        self::assertIsString($encrypted);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', (string) $encrypted);
        self::assertEquals($originalText, $encryptor->decryptForComponent($encrypted, 'my-component'));
    }

    public function testEncryptorStackNoAwsCredentials(): void
    {
        putenv('AWS_ACCESS_KEY_ID=fail');
        putenv('AWS_SECRET_ACCESS_KEY=fail');
        $encryptor = ObjectEncryptorFactory::getAwsEncryptor(
            'my-stack',
            self::getKmsKeyId(),
            self::getKmsRegion(),
            null
        );
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Encryption failed: Ciphering failed: Failed to obtain encryption key.');
        $encryptor->encryptForComponent('secret', 'some-component');
        // for azure, this test takes minutes to execute, so it is not included
    }

    public function unsupportedEncryptionInputProvider(): array
    {
        return [
            'invalid class' => [
                new class() {
                },
                'Only stdClass, array and string are supported types for encryption.',
            ],
            'invalid class in value' => [
                [
                    'key' => 'value',
                    'key2' => new class() {
                    },
                ],
                'Invalid item $key - only stdClass, array and scalar can be encrypted.',
            ],
            'invalid class in encrypted value' => [
                [
                    'key' => 'value',
                    '#key2' => new class() {
                    },
                ],
                'Invalid item $key - only stdClass, array and scalar can be encrypted.',
            ],
        ];
    }

    /**
     * @dataProvider unsupportedEncryptionInputProvider
     * @param array|stdClass|string $input
     */
    public function testEncryptorUnsupportedInput($input, string $expectedMessage): void
    {
        $encryptor = $this->getEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->encryptForComponent($input, 'my-component');
    }

    public function unsupportedDecryptionInputProvider(): array
    {
        return [
            'invalid class' => [
                new class() {
                },
                'Only stdClass, array and string are supported types for decryption.',
            ],
            'invalid class in value' => [
                [
                    'key' => 'value',
                    'key2' => new class() {
                    },
                ],
                'Invalid item key2 - only stdClass, array and scalar can be decrypted.',
            ],
            'invalid class in encrypted value' => [
                [
                    'key' => 'value',
                    '#key2' => new class() {
                    },
                ],
                'Invalid item #key2 - only stdClass, array and scalar can be decrypted.',
            ],
        ];
    }

    /**
     * @dataProvider unsupportedDecryptionInputProvider
     * @param array|stdClass|string $input
     */
    public function testDecryptorUnsupportedInput($input, string $expectedMessage): void
    {
        $encryptor = $this->getEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->decryptForComponent($input, 'my-component');
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
                            'looks like one lo1Sww=',
                    ],
                ],
                'Invalid cipher text for key #anotherKey Value "KBC::ComponentSecureKV::eJxLtDK2qs60Mrthis is not ' .
                'a valid cipher but it looks like one lo1Sww=" is not an encrypted value.',
            ],
            'completely off in key' => [
                [
                    'key1' => 'somevalue',
                    'key2' => [
                        '#anotherKey' => 'this does not even look like a cipher text',
                    ],
                ],
                'Invalid cipher text for key #anotherKey Value "this does not even look like a cipher text" ' .
                'is not an encrypted value.',
            ],
        ];
    }

    /**
     * @dataProvider decryptorInvalidCipherTextProvider
     * @param array|stdClass|string $encrypted
     */
    public function testDecryptorInvalidCipherText($encrypted, string $expectedMessage): void
    {
        $encryptor = $this->getEncryptor();
        self::expectException(UserException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->decryptForComponent($encrypted, 'my-component');
    }

    public function testEncryptorAlreadyEncrypted(): void
    {
        $encryptor = $this->getEncryptor();
        $data = [
            '#GenericKMSWrapper' => 'KBC::Secure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#GenericAKVWrapper' => 'KBC::SecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ComponentKMSWrapper' => 'KBC::ComponentSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ComponentAKVWrapper' => 'KBC::ComponentSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ProjectKMSWrapper' =>  'KBC::ProjectSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ProjectAKVWrapper' =>  'KBC::ProjectSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ConfigurationKMSWrapper' => 'KBC::ConfigSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ConfigurationAKVWrapper' => 'KBC::ConfigSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ProjectWideKMSWrapper' => 'KBC::ConfigSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ProjectWideAKVWrapper' => 'KBC::ConfigSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#Similar' => 'KBC::ConfigSecureKVaaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#Legacy1' => 'KBC::Encrypted==aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#Legacy2' => 'KBC::ComponentEncrypted==aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#Legacy3' => 'KBC::ComponentProjectEncrypted==aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#LegacySimilar' => 'KBC::Encryptedaaaaaaaaaaaaaaaaaaaaaaaaaa',
        ];
        $encryptedValue = $encryptor->encryptForComponent($data, 'my-component');
        self::assertIsArray($encryptedValue);
        // these two keys do not match exactly, and therefore are re-encrypted
        self::assertStringStartsWith('KBC::ComponentSecureKV::', (string) $encryptedValue['#Similar']);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', (string) $encryptedValue['#LegacySimilar']);

        // decrypt the two encrypted values, everything else should remain identical
        self::assertSame(
            'KBC::ConfigSecureKVaaaaaaaaaaaaaaaaaaaaaaaaaa',
            $encryptor->decryptForComponent($encryptedValue['#Similar'], 'my-component')
        );
        self::assertSame(
            'KBC::Encryptedaaaaaaaaaaaaaaaaaaaaaaaaaa',
            $encryptor->decryptForComponent($encryptedValue['#LegacySimilar'], 'my-component')
        );
        unset($data['#LegacySimilar']);
        unset($data['#Similar']);
        unset($encryptedValue['#LegacySimilar']);
        unset($encryptedValue['#Similar']);
        self::assertSame($data, $encryptedValue);
    }

    public function testEncryptorSimpleArray(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [
            'key1' => 'value1',
            '#key2' => 'value2',
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $result['#key2']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['#key2']);
    }

    public function testEncryptorSimpleObject(): void
    {
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $object->key1 = 'value1';
        $object->{'#key2'} = 'value2';

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('#key2', $result);
        self::assertEquals('value1', $result->key1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key2'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('#key2', $decrypted);
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->{'#key2'});
    }

    public function testEncryptorSimpleArrayScalars(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [
            'key1' => 'value1',
            '#key2' => 'value2',
            '#key3' => true,
            '#key4' => 1,
            '#key5' => 1.5,
            '#key6' => null,
            'key7' => null,
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertStringStartsWith('KBC::ComponentSecure', (string) $result['#key2']);
        self::assertStringStartsWith('KBC::ComponentSecure', (string) $result['#key3']);
        self::assertStringStartsWith('KBC::ComponentSecure', (string) $result['#key4']);
        self::assertStringStartsWith('KBC::ComponentSecure', (string) $result['#key5']);
        self::assertStringStartsWith('KBC::ComponentSecure', (string) $result['#key6']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
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
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $object->key1 = 'value1';
        $object->{'#key2'} = 'value2';
        $object->{'#key3'} = true;
        $object->{'#key4'} = 1;
        $object->{'#key5'} = 1.5;
        $object->{'#key6'} = null;
        $object->key7 = null;

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('#key2', $result);
        self::assertEquals('value1', $result->key1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key2'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key3'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key4'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key5'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key6'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
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
        $encryptor = $this->getEncryptor();
        $encryptedValue = $encryptor->encryptForComponent('test', 'my-component');
        $array = [
            'key1' => 'value1',
            '#key2' => $encryptedValue,
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals($encryptedValue, $result['#key2']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('test', $decrypted['#key2']);
    }

    public function testEncryptorSimpleObjectEncrypted(): void
    {
        $encryptor = $this->getEncryptor();
        $encryptedValue = $encryptor->encryptForComponent('test', 'my-component');
        $object = new stdClass();
        $object->key1 = 'value1';
        $object->{'#key2'} = $encryptedValue;

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertObjectHasAttribute('key1', $result);
        self::assertObjectHasAttribute('#key2', $result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals($encryptedValue, $result->{'#key2'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('#key2', $decrypted);
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('test', $decrypted->{'#key2'});
    }

    public function testEncryptorNestedArray(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [
            'key1' => 'value1',
            'key2' => [
                'nestedKey1' => 'value2',
                'nestedKey2' => [
                    '#finalKey' => 'value3',
                ],
            ],
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $result['key2']['nestedKey2']['#finalKey']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
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
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $nested1 = new stdClass();
        $nested2 = new stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested1->nestedKey1 = 'value2';
        $nested1->nestedKey2 = $nested2;
        $object->key1 = 'value1';
        $object->key2 = $nested1;

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
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
        $encryptor = $this->getEncryptor();
        $array = [
            'key1' => 'value1',
            'key2' => [
                'nestedKey1' => 'value2',
                'nestedKey2' => [
                    '#finalKey' => 'value3',
                ],
            ],
            '#key3' => [
                'anotherNestedKey' => 'someValue',
                '#encryptedNestedKey' => 'someValue2',
            ],
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertEquals('someValue', $result['#key3']['anotherNestedKey']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['#key3']['#encryptedNestedKey']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['key2']['nestedKey2']['#finalKey']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('key2', $decrypted);
        self::assertArrayHasKey('#key3', $decrypted);
        self::assertArrayHasKey('nestedKey1', $decrypted['key2']);
        self::assertArrayHasKey('nestedKey2', $decrypted['key2']);
        self::assertArrayHasKey('#finalKey', $decrypted['key2']['nestedKey2']);
        self::assertArrayHasKey('anotherNestedKey', $decrypted['#key3']);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['key2']['nestedKey1']);
        self::assertEquals('value3', $decrypted['key2']['nestedKey2']['#finalKey']);
        self::assertEquals('someValue', $decrypted['#key3']['anotherNestedKey']);
        self::assertEquals('someValue2', $decrypted['#key3']['#encryptedNestedKey']);
    }

    public function testEncryptorNestedObjectWithArrayKeyHashmark(): void
    {
        $encryptor = $this->getEncryptor();
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

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertEquals('someValue', $result->{'#key3'}->anotherNestedKey);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key3'}->{'#encryptedNestedKey'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('key2', $decrypted);
        self::assertObjectHasAttribute('#key3', $decrypted);
        self::assertObjectHasAttribute('nestedKey1', $decrypted->key2);
        self::assertObjectHasAttribute('nestedKey2', $decrypted->key2);
        self::assertObjectHasAttribute('#finalKey', $decrypted->key2->nestedKey2);
        self::assertObjectHasAttribute('anotherNestedKey', $decrypted->{'#key3'});
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->key2->nestedKey1);
        self::assertEquals('value3', $decrypted->key2->nestedKey2->{'#finalKey'});
        self::assertEquals('someValue', $decrypted->{'#key3'}->anotherNestedKey);
        self::assertEquals('someValue2', $decrypted->{'#key3'}->{'#encryptedNestedKey'});
    }

    public function testEncryptorNestedArrayEncrypted(): void
    {
        $encryptor = $this->getEncryptor();
        $encryptedValue = $encryptor->encryptForComponent('test', 'my-component');
        $array = [
            'key1' => 'value1',
            'key2' => [
                'nestedKey1' => 'value2',
                'nestedKey2' => [
                    '#finalKey' => 'value3',
                    '#finalKeyEncrypted' => $encryptedValue,
                ],
            ],
        ];

        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['key2']['nestedKey2']['#finalKey']);
        self::assertEquals($encryptedValue, $result['key2']['nestedKey2']['#finalKeyEncrypted']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
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
        $encryptor = $this->getEncryptor();
        $encryptedValue = $encryptor->encryptForComponent('test', 'my-component');

        $object = new stdClass();
        $object->key1 = 'value1';
        $nested1 = new stdClass();
        $nested1->nestedKey1 = 'value2';
        $nested2 = new stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested2->{'#finalKeyEncrypted'} = $encryptedValue;
        $nested1->nestedKey2 = $nested2;
        $object->key2 = $nested1;

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2->nestedKey2->{'#finalKey'});
        self::assertEquals($encryptedValue, $result->key2->nestedKey2->{'#finalKeyEncrypted'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
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
        $encryptor = $this->getEncryptor();
        $array = [
            'key1' => 'value1',
            'key2' => [
                ['nestedKey1' => 'value2'],
                ['nestedKey2' => ['#finalKey' => 'value3']],
            ],
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2'][0]['nestedKey1']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['key2'][1]['nestedKey2']['#finalKey']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
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
        $encryptor = $this->getEncryptor();
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

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2[0]->nestedKey1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2[1]->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
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
        $encryptor = $this->getEncryptor();
        $array = [
            '#key1' => $encryptor->encryptForComponent('value1', 'my-component'),
            '#key2' => $encryptor->encryptForProject('value2', 'my-component', 'my-project'),
        ];
        self::assertStringStartsWith('KBC::ComponentSecure', $array['#key1']);
        self::assertStringStartsWith('KBC::ProjectSecureKV::', $array['#key2']);

        $decrypted = $encryptor->decryptForProject($array, 'my-component', 'my-project');
        self::assertArrayHasKey('#key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertCount(2, $decrypted);
        self::assertEquals('value1', $decrypted['#key1']);
        self::assertEquals('value2', $decrypted['#key2']);
    }

    public function testMixedCryptoWrappersDecryptObject(): void
    {
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $object->{'#key1'} = $encryptor->encryptForComponent('value1', 'my-component');
        $object->{'#key2'} = $encryptor->encryptForProject('value2', 'my-component', 'my-project');

        self::assertStringStartsWith('KBC::ComponentSecureKV::', $object->{'#key1'});
        self::assertStringStartsWith('KBC::ProjectSecureKV::', $object->{'#key2'});

        $decrypted = $encryptor->decryptForProject($object, 'my-component', 'my-project');
        self::assertObjectHasAttribute('#key1', $decrypted);
        self::assertObjectHasAttribute('#key2', $decrypted);
        self::assertEquals('value1', $decrypted->{'#key1'});
        self::assertEquals('value2', $decrypted->{'#key2'});
    }

    public function testEncryptEmptyArray(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [];
        $encrypted = $encryptor->encryptForComponent($array, 'my-component');
        self::assertEquals([], $encrypted);
        self::assertEquals([], $encryptor->decryptForComponent($encrypted, 'my-component'));
    }

    public function testEncryptEmptyObject(): void
    {
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $encrypted = $encryptor->encryptForComponent($object, 'my-component');
        self::assertEquals(stdClass::class, get_class($encrypted));
        self::assertEquals(
            stdClass::class,
            get_class($encryptor->decryptForComponent($encrypted, 'my-component'))
        );
    }

    public function testEncryptorDecodedJSONObject(): void
    {
        $encryptor = $this->getEncryptor();
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

        $result = $encryptor->encryptForComponent(json_decode($json), 'my-component');
        self::assertIsObject($result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertEquals('someValue', $result->{'#key3'}->anotherNestedKey);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $result->{'#key3'}->{'#encryptedNestedKey'});
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $result->key2->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertObjectHasAttribute('key1', $decrypted);
        self::assertObjectHasAttribute('key2', $decrypted);
        self::assertObjectHasAttribute('#key3', $decrypted);
        self::assertObjectHasAttribute('array', $decrypted);
        self::assertObjectHasAttribute('emptyArray', $decrypted);
        self::assertObjectHasAttribute('emptyObject', $decrypted);
        self::assertObjectHasAttribute('nestedKey1', $decrypted->key2);
        self::assertObjectHasAttribute('nestedKey2', $decrypted->key2);
        self::assertObjectHasAttribute('#finalKey', $decrypted->key2->nestedKey2);
        self::assertIsArray($decrypted->array);
        self::assertIsArray($decrypted->emptyArray);
        self::assertIsObject($decrypted->emptyObject);
        self::assertIsObject($decrypted->key2);
        self::assertObjectHasAttribute('anotherNestedKey', $decrypted->{'#key3'});
        self::assertIsObject($decrypted->{'#key3'});
        self::assertEquals('value1', $decrypted->key1);
        self::assertObjectHasAttribute('nestedKey1', $decrypted->key2);
        self::assertEquals('value2', $decrypted->key2->nestedKey1);
        self::assertObjectHasAttribute('anotherNestedKey', $decrypted->{'#key3'});
        self::assertEquals('someValue', $decrypted->{'#key3'}->{'anotherNestedKey'});
        self::assertObjectHasAttribute('#encryptedNestedKey', $decrypted->{'#key3'});
        self::assertEquals('someValue2', $decrypted->{'#key3'}->{'#encryptedNestedKey'});
        self::assertObjectHasAttribute('nestedKey2', $decrypted->key2);
        self::assertEquals('value3', $decrypted->key2->nestedKey2->{'#finalKey'});

        self::assertEquals(json_encode($decrypted), json_encode(json_decode($json)));
    }

    public function cloudEncryptorProvider(): Generator
    {
        yield 'azure' => [
            'encryptor' => ObjectEncryptorFactory::getAzureEncryptor(
                'my-stack',
                self::getAkvUrl()
            ),
            'genericPrefix' => 'KBC::SecureKV::',
            'componentPrefix' => 'KBC::ComponentSecureKV::',
            'projectPrefix' => 'KBC::ProjectSecureKV::',
            'configurationPrefix' => 'KBC::ConfigSecureKV::',
            'projectWidePrefix' => 'KBC::ProjectWideSecureKV::',
        ];
        yield 'aws' => [
            'encryptor' => ObjectEncryptorFactory::getAwsEncryptor(
                'my-stack',
                self::getKmsKeyId(),
                self::getKmsRegion(),
                null
            ),
            'genericPrefix' => 'KBC::Secure::',
            'componentPrefix' => 'KBC::ComponentSecure::',
            'projectPrefix' => 'KBC::ProjectSecure::',
            'configurationPrefix' => 'KBC::ConfigSecure::',
            'projectWidePrefix' => 'KBC::ProjectWideSecure::',
        ];
    }

    /**
     * @dataProvider cloudEncryptorProvider
     */
    public function testGetRegisteredWrapperEncryptors(
        ObjectEncryptor $encryptor,
        string $genericPrefix,
        string $componentPrefix,
        string $projectPrefix,
        string $configurationPrefix,
        string $projectWidePrefix
    ): void {
        $encryptedGeneric = $encryptor->encryptGeneric('secret1');
        self::assertStringStartsWith($genericPrefix, $encryptedGeneric);
        self::assertEquals('secret1', $encryptor->decryptGeneric($encryptedGeneric));

        $encryptedComponent = $encryptor->encryptForComponent('secret2', 'my-component');
        self::assertStringStartsWith($componentPrefix, $encryptedComponent);
        self::assertEquals('secret1', $encryptor->decryptForComponent($encryptedGeneric, 'my-component'));
        self::assertEquals('secret2', $encryptor->decryptForComponent($encryptedComponent, 'my-component'));

        $encryptedProject = $encryptor->encryptForProject('secret3', 'my-component', 'my-project');
        self::assertStringStartsWith($projectPrefix, $encryptedProject);
        self::assertEquals(
            'secret1',
            $encryptor->decryptForProject($encryptedGeneric, 'my-component', 'my-project')
        );
        self::assertEquals(
            'secret2',
            $encryptor->decryptForProject($encryptedComponent, 'my-component', 'my-project')
        );
        self::assertEquals(
            'secret3',
            $encryptor->decryptForProject($encryptedProject, 'my-component', 'my-project')
        );

        $encryptedConfiguration = $encryptor->encryptForConfiguration(
            'secret4',
            'my-component',
            'my-project',
            'my-configuration'
        );
        self::assertStringStartsWith($configurationPrefix, $encryptedConfiguration);
        self::assertEquals(
            'secret1',
            $encryptor->decryptForConfiguration(
                $encryptedGeneric,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );
        self::assertEquals(
            'secret2',
            $encryptor->decryptForConfiguration(
                $encryptedComponent,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );
        self::assertEquals(
            'secret3',
            $encryptor->decryptForConfiguration(
                $encryptedProject,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );
        self::assertEquals(
            'secret4',
            $encryptor->decryptForConfiguration(
                $encryptedConfiguration,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );

        $encryptedProjectWide = $encryptor->encryptForProjectWide('secret2', 'my-project');
        self::assertStringStartsWith($projectWidePrefix, $encryptedProjectWide);
        self::assertEquals('secret1', $encryptor->decryptForProjectWide($encryptedGeneric, 'my-project'));
        self::assertEquals('secret2', $encryptor->decryptForProjectWide($encryptedProjectWide, 'my-project'));
    }
}
