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

    /**
     * @param string|array|stdClass $data Data to encrypt
     * @return string|array|stdClass
     * @throws ApplicationException
     * @throws UserException
     */
    public function encrypt($data, string $wrapperName)
    {
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
    public function decrypt($data)
    {
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
    public function pushWrapper(CryptoWrapperInterface $wrapper)
    {
        if (isset($this->wrappers[$wrapper->getPrefix()])) {
            throw new ApplicationException('CryptoWrapper prefix ' . $wrapper->getPrefix() . ' is not unique.');
        }
        $this->wrappers[$wrapper->getPrefix()] = $wrapper;
    }

    public function getRegisteredComponentWrapperClass(): string
    {
        foreach ($this->wrappers as $wrapper) {
            if (get_class($wrapper) === ComponentKMSWrapper::class ||
                get_class($wrapper) === ComponentAKVWrapper::class) {
                return get_class($wrapper);
            }
        }
        throw new ApplicationException('No Component wrappers registered.');
    }

    public function getRegisteredProjectWrapperClass(): string
    {
        foreach ($this->wrappers as $wrapper) {
            if (get_class($wrapper) === ProjectKMSWrapper::class || get_class($wrapper) === ProjectAKVWrapper::class) {
                return get_class($wrapper);
            }
        }
        throw new ApplicationException('No Project wrappers registered.');
    }

    public function getRegisteredConfigurationWrapperClass(): string
    {
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
}
