<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor;

use Exception;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;
use stdClass;
use Throwable;

class ObjectEncryptor
{
    /**
     * List of known wrappers.
     * @var CryptoWrapperInterface[]
     */
    private array $wrappers = [];

    public function encryptForComponent($data, string $componentId)
    {
    }

    public function encryptForProject($data, string $componentId, string $projectId)
    {
    }

    public function encryptForConfiguration($data, string $componentId, string $projectId, string $configurationId)
    {
    }

    public function decryptForComponent($data, string $componentId)
    {
    }

    public function decryptForProject($data, string $componentId, string $projectId)
    {
    }

    public function decryptForConfiguration($data, string $componentId, string $projectId, string $configurationId)
    {
    }

    public function __construct(EncryptorOptions $encryptorOptions)
    {
    }

    //parametry povinny a neprazdny

    /**
     * @param string|array|stdClass $data Data to encrypt
     * @return string|array|stdClass
     * @throws ApplicationException
     * @throws UserException
     */
    private function encrypt($data, string $wrapperName)
    {
        // @todo to be deleted
        foreach ($this->wrappers as $cryptoWrapper) {
            if (get_class($cryptoWrapper) === $wrapperName) {
                $wrapper = $cryptoWrapper;
                break;
            }
        }
        if (empty($wrapper)) {
            throw new ApplicationException('Invalid crypto wrapper ' . $wrapperName);
        }
        if (is_scalar($data)) {
            return $this->encryptValue((string) $data, $wrapper);
        }
        if (is_array($data)) {
            return $this->encryptArray($data, $wrapper);
        }
        if (is_object($data) && get_class($data) === stdClass::class) {
            return $this->encryptObject($data, $wrapper);
        }
        throw new ApplicationException('Only stdClass, array and string are supported types for encryption.');
    }

    /**
     * @param string|array|stdClass $data
     * @return string|array|stdClass
     * @throws ApplicationException
     * @throws UserException
     */
    private function decrypt($data)
    {
        // @todo to be deleted
        if (is_scalar($data)) {
            return $this->decryptValue($data);
        }
        if (is_array($data)) {
            return $this->decryptArray($data);
        }
        if (is_a($data, stdClass::class) && (get_class($data) === stdClass::class)) {
            return $this->decryptObject($data);
        }
        throw new ApplicationException('Only stdClass, array and string are supported types for decryption.');
    }

    /**
     * Manually add a known crypto wrapper. Generally, wrappers should be added to services.yml with tag
     * 'syrup.encryption.wrapper' - that way, they will be added automatically.
     * @param CryptoWrapperInterface $wrapper
     * @throws ApplicationException
     */
    private function pushWrapper(CryptoWrapperInterface $wrapper)
    {
        // @todo to be deleted
        if (isset($this->wrappers[$wrapper->getPrefix()])) {
            throw new ApplicationException('CryptoWrapper prefix ' . $wrapper->getPrefix() . ' is not unique.');
        }
        $this->wrappers[$wrapper->getPrefix()] = $wrapper;
    }

    private function getRegisteredComponentWrapperClass(): string
    {
        // @todo to be deleted
        foreach ($this->wrappers as $wrapper) {
            if (get_class($wrapper) === ComponentKMSWrapper::class ||
                get_class($wrapper) === ComponentAKVWrapper::class) {
                return get_class($wrapper);
            }
        }
        throw new ApplicationException('No Component wrappers registered.');
    }

    private function getRegisteredProjectWrapperClass(): string
    {
        // @todo to be deleted
        foreach ($this->wrappers as $wrapper) {
            if (get_class($wrapper) === ProjectKMSWrapper::class || get_class($wrapper) === ProjectAKVWrapper::class) {
                return get_class($wrapper);
            }
        }
        throw new ApplicationException('No Project wrappers registered.');
    }

    private function getRegisteredConfigurationWrapperClass(): string
    {
        // @todo to be deleted
        foreach ($this->wrappers as $wrapper) {
            if (get_class($wrapper) === ConfigurationKMSWrapper::class ||
                get_class($wrapper) === ConfigurationAKVWrapper::class) {
                return get_class($wrapper);
            }
        }
        throw new ApplicationException('No Configuration wrappers registered.');
    }

    /**
     * Find a wrapper to decrypt a given cipher.
     */
    private function findWrapper(string $value): ?CryptoWrapperInterface
    {
        $selectedWrapper = null;
        foreach ($this->wrappers as $wrapper) {
            if (substr($value, 0, mb_strlen($wrapper->getPrefix())) === $wrapper->getPrefix()) {
                $selectedWrapper = $wrapper;
            }
        }
        return $selectedWrapper;
    }

    private function decryptValue(string $value): string
    {
        $wrapper = $this->findWrapper($value);
        if (!$wrapper) {
            throw new UserException(sprintf('Value "%s" is not an encrypted value.', $value), 0);
        } else {
            try {
                return $wrapper->decrypt(substr($value, mb_strlen($wrapper->getPrefix())));
            } catch (UserException $e) {
                throw new UserException(sprintf('Value "%s" is not an encrypted value.', $value), $e->getCode(), $e);
            } catch (Throwable $e) {
                // decryption failed for more serious reasons
                throw new ApplicationException('Decryption failed: ' . $e->getMessage(), $e->getCode(), $e);
            }
        }
    }

    /**
     * @param string|int $key
     * @param array|string|stdClass|null $value Value to encrypt.
     * @return array|string|stdClass|null
     */
    private function encryptItem($key, $value, CryptoWrapperInterface $wrapper)
    {
        if (is_scalar($value) || is_null($value)) {
            if (substr((string) $key, 0, 1) === '#') {
                return $this->encryptValue((string) $value, $wrapper);
            } else {
                return $value;
            }
        } elseif (is_array($value)) {
            return $this->encryptArray($value, $wrapper);
        } elseif (is_object($value) && get_class($value) === stdClass::class) {
            return $this->encryptObject($value, $wrapper);
        } else {
            throw new ApplicationException(
                'Invalid item $key - only stdClass, array and scalar can be encrypted.'
            );
        }
    }

    private function encryptValue(string $value, CryptoWrapperInterface $wrapper): string
    {
        // return self if already encrypted with any wrapper
        if ($this->findWrapper($value)) {
            return $value;
        }

        try {
            return $wrapper->getPrefix() . $wrapper->encrypt($value);
        } catch (Throwable $e) {
            throw new ApplicationException('Encryption failed: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    private function encryptArray(array $data, CryptoWrapperInterface $wrapper): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            $result[$key] = $this->encryptItem($key, $value, $wrapper);
        }
        return $result;
    }

    private function encryptObject(stdClass $data, CryptoWrapperInterface $wrapper): stdClass
    {
        $result = new stdClass();
        foreach (get_object_vars($data) as $key => $value) {
            $result->{$key} = $this->encryptItem($key, $value, $wrapper);
        }
        return $result;
    }

    /**
     * @param string|int $key
     * @param array|string|stdClass|null $value Value to decrypt.
     * @return array|string|stdClass|null Decrypted value.
     */
    private function decryptItem($key, $value)
    {
        if (is_scalar($value) || is_null($value)) {
            if (substr((string) $key, 0, 1) === '#') {
                try {
                    return $this->decryptValue((string) $value);
                } catch (UserException $e) {
                    throw new UserException("Invalid cipher text for key $key " . $e->getMessage(), $e->getCode(), $e);
                }
            } else {
                return $value;
            }
        } elseif (is_array($value)) {
            return $this->decryptArray($value);
        } elseif (is_object($value) && get_class($value) === stdClass::class) {
            return $this->decryptObject($value);
        } else {
            throw new ApplicationException(
                "Invalid item $key - only stdClass, array and scalar can be decrypted."
            );
        }
    }

    private function decryptObject(stdClass $data): stdClass
    {
        $result = new stdClass();
        foreach (get_object_vars($data) as $key => $value) {
            $result->{$key} = $this->decryptItem($key, $value);
        }
        return $result;
    }

    private function decryptArray(array $data): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            $result[$key] = $this->decryptItem($key, $value);
        }
        return $result;
    }

    /**
     * @param ObjectEncryptor $encryptor
     * @throws ApplicationException
     */
    private function addKMSWrappers(ObjectEncryptor $encryptor): void
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId((string) $this->kmsKeyId);
        $wrapper->setKMSRegion((string) $this->kmsKeyRegion);
        $encryptor->pushWrapper($wrapper);

        if ($this->componentId && $this->stackId) {
            $wrapper = new ComponentKMSWrapper();
            $wrapper->setKMSKeyId((string) $this->kmsKeyId);
            $wrapper->setKMSRegion((string) $this->kmsKeyRegion);
            $wrapper->setComponentId($this->componentId);
            $wrapper->setStackId($this->stackId);
            $encryptor->pushWrapper($wrapper);
            if ($this->projectId) {
                $wrapper = new ProjectKMSWrapper();
                $wrapper->setKMSKeyId((string) $this->kmsKeyId);
                $wrapper->setKMSRegion((string) $this->kmsKeyRegion);
                $wrapper->setComponentId($this->componentId);
                $wrapper->setStackId($this->stackId);
                $wrapper->setProjectId($this->projectId);
                $encryptor->pushWrapper($wrapper);
                if ($this->configurationId) {
                    $wrapper = new ConfigurationKMSWrapper();
                    $wrapper->setKMSKeyId((string) $this->kmsKeyId);
                    $wrapper->setKMSRegion((string) $this->kmsKeyRegion);
                    $wrapper->setComponentId($this->componentId);
                    $wrapper->setStackId($this->stackId);
                    $wrapper->setProjectId($this->projectId);
                    $wrapper->setConfigurationId($this->configurationId);
                    $encryptor->pushWrapper($wrapper);
                }
            }
        }
    }

    /**
     * @param ObjectEncryptor $encryptor
     * @throws ApplicationException
     */
    private function addAKVWrappers(ObjectEncryptor $encryptor): void
    {
        $wrapper = new GenericAKVWrapper();
        $wrapper->setKeyVaultUrl((string) $this->akvUrl);
        $encryptor->pushWrapper($wrapper);

        if ($this->componentId && $this->stackId) {
            $wrapper = new ComponentAKVWrapper();
            $wrapper->setKeyVaultUrl((string) $this->akvUrl);
            $wrapper->setComponentId($this->componentId);
            $wrapper->setStackId($this->stackId);
            $encryptor->pushWrapper($wrapper);
            if ($this->projectId) {
                $wrapper = new ProjectAKVWrapper();
                $wrapper->setKeyVaultUrl((string) $this->akvUrl);
                $wrapper->setComponentId($this->componentId);
                $wrapper->setStackId($this->stackId);
                $wrapper->setProjectId($this->projectId);
                $encryptor->pushWrapper($wrapper);
                if ($this->configurationId) {
                    $wrapper = new ConfigurationAKVWrapper();
                    $wrapper->setKeyVaultUrl((string) $this->akvUrl);
                    $wrapper->setComponentId($this->componentId);
                    $wrapper->setStackId($this->stackId);
                    $wrapper->setProjectId($this->projectId);
                    $wrapper->setConfigurationId($this->configurationId);
                    $encryptor->pushWrapper($wrapper);
                }
            }
        }
    }
}
