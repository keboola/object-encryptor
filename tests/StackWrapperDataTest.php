<?php

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Wrapper\StackWrapper;
use PHPUnit\Framework\TestCase;

class StackWrapperDataTest extends TestCase
{

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid cipher
     */
    public function testDecryptInvalidKey()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $encrypted = base64_encode(Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyGeneral)));
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Deserialization of decrypted data failed: Syntax error
     */
    public function testDecryptInvalidJson()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $encrypted = base64_encode(Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyGeneral)));
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid stack
     */
    public function testDecryptInvalidJson2()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['foo' => 'bar']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid cipher
     */
    public function testDecryptInvalidJson3()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => 'foo']]),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->decrypt($encrypted);
    }

    public function testDecryptValidJson()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher]]),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $decrypted = $stackWrapper->decrypt($encrypted);
        self::assertEquals('fooBar', $decrypted);
    }

    public function testDecryptValidJsonMultipleStacks()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher1 = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $inCipher2 = Crypto::encrypt('barKochba', Key::loadFromAsciiSafeString($keyStack));
        $inCipher3 = Crypto::encrypt('barFoo', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(
                    ['stacks' =>
                        ['my-stack' => $inCipher1, 'another-stack' => $inCipher2, 'yet-another-stack' => $inCipher3]
                    ]
                ),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('another-stack');
        $decrypted = $stackWrapper->decrypt($encrypted);
        self::assertEquals('barKochba', $decrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid cipher
     */
    public function testDecryptValidJsonMultipleStacksWrongKeys()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher1 = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $inCipher2 = Crypto::encrypt('barKochba', Key::createNewRandomKey());
        $inCipher3 = Crypto::encrypt('barFoo', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(
                    ['stacks' =>
                        ['my-stack' => $inCipher1, 'another-stack' => $inCipher2, 'yet-another-stack' => $inCipher3]
                    ]
                ),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('another-stack');
        $decrypted = $stackWrapper->decrypt($encrypted);
        self::assertEquals('barKochba', $decrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid cipher
     */
    public function testDecryptWrongStackKey()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::createNewRandomKey());
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher]]),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid stack
     */
    public function testWrongStack()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['not-my-stack' => $inCipher]]),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->decrypt($encrypted);
    }

    public function testNoComponent()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher]]),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('keboola.demo-app');
        $stackWrapper->decrypt($encrypted);
    }

    public function testValidComponent()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher], 'cmp' => 'keboola.docker-demo-app']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('keboola.docker-demo-app');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid component
     */
    public function testWrongComponent1()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher], 'cmp' => 'keboola.docker-demo-app']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid component
     */
    public function testWrongComponent2()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher], 'cmp' => 'keboola.docker-demo-app']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('different-component');
        $stackWrapper->decrypt($encrypted);
    }

    public function testNoProject()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher]]),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setProjectId('123');
        $stackWrapper->decrypt($encrypted);
    }

    public function testValidProject()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher], 'prj' => '123']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('123');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid project
     */
    public function testWrongProject1()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher], 'prj' => '123']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid project
     */
    public function testWrongProject2()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher], 'prj' => '123']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('321');
        $stackWrapper->decrypt($encrypted);
    }

    public function testNoConfiguration()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher], 'cfg' => '12345']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setConfigurationId('12345');
        $stackWrapper->decrypt($encrypted);
    }

    public function testValidConfiguration()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher], 'cfg' => '12345']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setConfigurationId('12345');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid configuration
     */
    public function testWrongConfiguration1()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher], 'cfg' => '12345']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid configuration
     */
    public function testWrongConfiguration2()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(['stacks' => ['my-stack' => $inCipher], 'cfg' => '12345']),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setConfigurationId('54321');
        $stackWrapper->decrypt($encrypted);
    }

    public function testValidComponentProjectConfiguration()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(
                    [
                        'stacks' => ['my-stack' => $inCipher],
                        'cmp' => 'keboola.docker-demo-app',
                        'prj' => 123,
                        'cfg' => '12345'
                    ]
                ),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('keboola.docker-demo-app');
        $stackWrapper->setProjectId('123');
        $stackWrapper->setConfigurationId('12345');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid component
     */
    public function testInvalidValidComponentProjectConfiguration1()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(
                    [
                        'stacks' => ['my-stack' => $inCipher],
                        'cmp' => 'keboola.docker-demo-app',
                        'prj' => 123,
                        'cfg' => '12345'
                    ]
                ),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('not-my-component');
        $stackWrapper->setProjectId('123');
        $stackWrapper->setConfigurationId('12345');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid configuration
     */
    public function testInvalidValidComponentProjectConfiguration2()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(
                    [
                        'stacks' => ['my-stack' => $inCipher],
                        'cmp' => 'keboola.docker-demo-app',
                        'prj' => 123,
                        'cfg' => '12345'
                    ]
                ),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('keboola.docker-demo-app');
        $stackWrapper->setProjectId('321');
        $stackWrapper->setConfigurationId('12345');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid project
     */
    public function testInvalidValidComponentProjectConfiguration3()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(
                    [
                        'stacks' => ['my-stack' => $inCipher],
                        'cmp' => 'keboola.docker-demo-app',
                        'prj' => 123,
                        'cfg' => '12345'
                    ]
                ),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('keboola.docker-demo-app');
        $stackWrapper->setProjectId('123');
        $stackWrapper->setConfigurationId('54321');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid stack
     */
    public function testInvalidValidComponentProjectConfiguration4()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = base64_encode(
            Crypto::encrypt(
                json_encode(
                    [
                        'stacks' => ['my-stack' => $inCipher],
                        'cmp' => 'keboola.docker-demo-app',
                        'prj' => 123,
                        'cfg' => '12345'
                    ]
                ),
                Key::loadFromAsciiSafeString($keyGeneral)
            )
        );
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($keyGeneral);
        $stackWrapper->setStackKey($keyStack);
        $stackWrapper->setStackId('not-my-stack');
        $stackWrapper->setComponentId('keboola.docker-demo-app');
        $stackWrapper->setProjectId('123');
        $stackWrapper->setConfigurationId('54321');
        $stackWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid component
     */
    public function testAddInvalidComponent()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($generalKey);
        $stackWrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('keboola.docker-demo');
        $stackWrapper->setConfigurationId('123456');
        $stackWrapper->setProjectId('123');
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('CPF::', $encrypted);
        $stackWrapper2 = new StackWrapper();
        $stackWrapper2->setGeneralKey($generalKey);
        $stackWrapper2->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper2->setStackId('another-stack');
        $stackWrapper2->setComponentId('some-different-component');
        $stackWrapper2->setConfigurationId('123456');
        $stackWrapper2->setProjectId('123');
        $stackWrapper2->add($encrypted, "anotherSecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Stack is already used
     */
    public function testAddInvalidOverwrite()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($generalKey);
        $stackWrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('keboola.docker-demo');
        $stackWrapper->setConfigurationId('123456');
        $stackWrapper->setProjectId('123');
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('CPF::', $encrypted);
        $stackWrapper2 = new StackWrapper();
        $stackWrapper2->setGeneralKey($generalKey);
        $stackWrapper2->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper2->setStackId('my-stack');
        $stackWrapper2->setComponentId('keboola.docker-demo');
        $stackWrapper2->setConfigurationId('123456');
        $stackWrapper2->setProjectId('123');
        $stackWrapper2->add($encrypted, "anotherSecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\EncryptionException
     * @expectedExceptionMessage Invalid cipher
     */
    public function testAddInvalidKey()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($generalKey);
        $stackWrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId('keboola.docker-demo');
        $stackWrapper->setConfigurationId('123456');
        $stackWrapper->setProjectId('123');
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('CPF::', $encrypted);
        $stackWrapper2 = new StackWrapper();
        $stackWrapper2->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper2->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper2->setStackId('another-stack');
        $stackWrapper2->setComponentId('keboola.docker-demo');
        $stackWrapper2->setConfigurationId('123456');
        $stackWrapper2->setProjectId('123');
        $stackWrapper2->add($encrypted, "anotherSecretValue");
    }
}
