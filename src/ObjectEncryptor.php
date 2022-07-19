<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor;

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
    private EncryptorOptions $encryptorOptions;

    public function __construct(EncryptorOptions $encryptorOptions)
    {
        $this->encryptorOptions = $encryptorOptions;
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function encryptGeneric($data)
    {
        $wrappers = $this->getWrappers(null, null, null);
        return $this->encrypt(
            $data,
            $wrappers,
            $this->encryptorOptions->getAkvUrl() ? GenericAKVWrapper::class : GenericKMSWrapper::class
        );
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function encryptForComponent($data, string $componentId)
    {
        $wrappers = $this->getWrappers($componentId, null, null);
        return $this->encrypt(
            $data,
            $wrappers,
            $this->encryptorOptions->getAkvUrl() ? ComponentAKVWrapper::class : ComponentKMSWrapper::class
        );
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function encryptForProject($data, string $componentId, string $projectId)
    {
        $wrappers = $this->getWrappers($componentId, $projectId, null);
        return $this->encrypt(
            $data,
            $wrappers,
            $this->encryptorOptions->getAkvUrl() ? ProjectAKVWrapper::class : ProjectKMSWrapper::class
        );
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function encryptForConfiguration($data, string $componentId, string $projectId, string $configurationId)
    {
        $wrappers = $this->getWrappers($componentId, $projectId, $configurationId);
        return $this->encrypt(
            $data,
            $wrappers,
            $this->encryptorOptions->getAkvUrl() ? ConfigurationAKVWrapper::class : ConfigurationKMSWrapper::class
        );
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function decryptGeneric($data)
    {
        $wrappers = $this->getWrappers(null, null, null);
        return $this->decrypt($data, $wrappers);
    }


    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function decryptForComponent($data, string $componentId)
    {
        $wrappers = $this->getWrappers($componentId, null, null);
        return $this->decrypt($data, $wrappers);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function decryptForProject($data, string $componentId, string $projectId)
    {
        $wrappers = $this->getWrappers($componentId, $projectId, null);
        return $this->decrypt($data, $wrappers);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function decryptForConfiguration($data, string $componentId, string $projectId, string $configurationId)
    {
        $wrappers = $this->getWrappers($componentId, $projectId, $configurationId);
        return $this->decrypt($data, $wrappers);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data Data to encrypt
     * @return T
     * @throws ApplicationException
     * @throws UserException
     */
    private function encrypt($data, array $wrappers, string $wrapperName)
    {
        foreach ($wrappers as $cryptoWrapper) {
            if (get_class($cryptoWrapper) === $wrapperName) {
                $wrapper = $cryptoWrapper;
                break;
            }
        }
        if (empty($wrapper)) {
            throw new ApplicationException('Invalid crypto wrapper ' . $wrapperName);
        }
        if (is_scalar($data)) {
            return $this->encryptValue((string) $data, $wrappers, $wrapper);
        }
        if (is_array($data)) {
            return $this->encryptArray($data, $wrappers, $wrapper);
        }
        if ($data instanceof stdClass) {
            return $this->encryptObject($data, $wrappers, $wrapper);
        }
        // @phpstan-ignore-next-line
        throw new ApplicationException('Only stdClass, array and string are supported types for encryption.');
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     * @throws ApplicationException
     * @throws UserException
     */
    private function decrypt($data, array $wrappers)
    {
        if (is_scalar($data)) {
            return $this->decryptValue($data, $wrappers);
        }
        if (is_array($data)) {
            return $this->decryptArray($data, $wrappers);
        }
        if ($data instanceof stdClass) {
            return $this->decryptObject($data, $wrappers);
        }
        // @phpstan-ignore-next-line
        throw new ApplicationException('Only stdClass, array and string are supported types for decryption.');
    }

    private function findWrapper(string $value, array $wrappers): ?CryptoWrapperInterface
    {
        $selectedWrapper = null;
        foreach ($wrappers as $wrapper) {
            if (substr($value, 0, mb_strlen($wrapper->getPrefix())) === $wrapper->getPrefix()) {
                $selectedWrapper = $wrapper;
            }
        }
        return $selectedWrapper;
    }

    private function decryptValue(string $value, array $wrappers): string
    {
        $wrapper = $this->findWrapper($value, $wrappers);
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
     * @param mixed $value Value to encrypt.
     * @return array|bool|float|int|stdClass|string|null
     */
    private function encryptItem($key, $value, array $wrappers, CryptoWrapperInterface $wrapper)
    {
        if (is_scalar($value) || is_null($value)) {
            if (substr((string) $key, 0, 1) === '#') {
                return $this->encryptValue((string) $value, $wrappers, $wrapper);
            } else {
                return $value;
            }
        } elseif (is_array($value)) {
            return $this->encryptArray($value, $wrappers, $wrapper);
        } elseif ($value instanceof stdClass) {
            return $this->encryptObject($value, $wrappers, $wrapper);
        } else {
            throw new ApplicationException(
                'Invalid item $key - only stdClass, array and scalar can be encrypted.'
            );
        }
    }

    private function encryptValue(string $value, array $wrappers, CryptoWrapperInterface $wrapper): string
    {
        // return self if already encrypted with any wrapper
        if ($this->findWrapper($value, $wrappers)) {
            return $value;
        }

        try {
            return $wrapper->getPrefix() . $wrapper->encrypt($value);
        } catch (Throwable $e) {
            throw new ApplicationException('Encryption failed: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    private function encryptArray(array $data, array $wrappers, CryptoWrapperInterface $wrapper): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            $result[$key] = $this->encryptItem($key, $value, $wrappers, $wrapper);
        }
        return $result;
    }

    private function encryptObject(stdClass $data, array $wrappers, CryptoWrapperInterface $wrapper): stdClass
    {
        $result = new stdClass();
        foreach (get_object_vars($data) as $key => $value) {
            $result->{$key} = $this->encryptItem($key, $value, $wrappers, $wrapper);
        }
        return $result;
    }

    /**
     * @param string|int $key
     * @param mixed $value Value to decrypt.
     * @return array|bool|float|int|stdClass|string|null Decrypted value.
     */
    private function decryptItem($key, $value, array $wrappers)
    {
        if (is_scalar($value) || is_null($value)) {
            if (substr((string) $key, 0, 1) === '#') {
                try {
                    return $this->decryptValue((string) $value, $wrappers);
                } catch (UserException $e) {
                    throw new UserException("Invalid cipher text for key $key " . $e->getMessage(), $e->getCode(), $e);
                }
            } else {
                return $value;
            }
        } elseif (is_array($value)) {
            return $this->decryptArray($value, $wrappers);
        } elseif ($value instanceof stdClass) {
            return $this->decryptObject($value, $wrappers);
        } else {
            throw new ApplicationException(
                "Invalid item $key - only stdClass, array and scalar can be decrypted."
            );
        }
    }

    private function decryptObject(stdClass $data, array $wrappers): stdClass
    {
        $result = new stdClass();
        foreach (get_object_vars($data) as $key => $value) {
            $result->{$key} = $this->decryptItem($key, $value, $wrappers);
        }
        return $result;
    }

    private function decryptArray(array $data, array $wrappers): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            $result[$key] = $this->decryptItem($key, $value, $wrappers);
        }
        return $result;
    }

    private function getKMSWrappers(?string $componentId, ?string $projectId, ?string $configurationId): array
    {
        $wrappers = [];
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId((string) $this->encryptorOptions->getKmsKeyId());
        $wrapper->setKMSRegion((string) $this->encryptorOptions->getKmsKeyRegion());
        $wrappers[] = $wrapper;

        if ($componentId && $this->encryptorOptions->getStackId()) {
            $wrapper = new ComponentKMSWrapper();
            $wrapper->setKMSKeyId((string) $this->encryptorOptions->getKmsKeyId());
            $wrapper->setKMSRegion((string) $this->encryptorOptions->getKmsKeyRegion());
            $wrapper->setComponentId($componentId);
            $wrapper->setStackId($this->encryptorOptions->getStackId());
            $wrappers[] = $wrapper;
            if ($projectId) {
                $wrapper = new ProjectKMSWrapper();
                $wrapper->setKMSKeyId((string) $this->encryptorOptions->getKmsKeyId());
                $wrapper->setKMSRegion((string) $this->encryptorOptions->getKmsKeyRegion());
                $wrapper->setComponentId($componentId);
                $wrapper->setStackId($this->encryptorOptions->getStackId());
                $wrapper->setProjectId($projectId);
                $wrappers[] = $wrapper;
                if ($configurationId) {
                    $wrapper = new ConfigurationKMSWrapper();
                    $wrapper->setKMSKeyId((string) $this->encryptorOptions->getKmsKeyId());
                    $wrapper->setKMSRegion((string) $this->encryptorOptions->getKmsKeyRegion());
                    $wrapper->setComponentId($componentId);
                    $wrapper->setStackId($this->encryptorOptions->getStackId());
                    $wrapper->setProjectId($projectId);
                    $wrapper->setConfigurationId($configurationId);
                    $wrappers[] = $wrapper;
                }
            }
        }
        return $wrappers;
    }

    private function getAKVWrappers(?string $componentId, ?string $projectId, ?string $configurationId): array
    {
        $wrappers = [];
        $wrapper = new GenericAKVWrapper();
        $wrapper->setKeyVaultUrl((string) $this->encryptorOptions->getAkvUrl());
        $wrappers[] = $wrapper;
        if ($componentId && $this->encryptorOptions->getStackId()) {
            $wrapper = new ComponentAKVWrapper();
            $wrapper->setKeyVaultUrl((string) $this->encryptorOptions->getAkvUrl());
            $wrapper->setComponentId($componentId);
            $wrapper->setStackId($this->encryptorOptions->getStackId());
            $wrappers[] = $wrapper;
            if ($projectId) {
                $wrapper = new ProjectAKVWrapper();
                $wrapper->setKeyVaultUrl((string) $this->encryptorOptions->getAkvUrl());
                $wrapper->setComponentId($componentId);
                $wrapper->setStackId($this->encryptorOptions->getStackId());
                $wrapper->setProjectId($projectId);
                $wrappers[] = $wrapper;
                if ($configurationId) {
                    $wrapper = new ConfigurationAKVWrapper();
                    $wrapper->setKeyVaultUrl((string) $this->encryptorOptions->getAkvUrl());
                    $wrapper->setComponentId($componentId);
                    $wrapper->setStackId($this->encryptorOptions->getStackId());
                    $wrapper->setProjectId($projectId);
                    $wrapper->setConfigurationId($configurationId);
                    $wrappers[] = $wrapper;
                }
            }
        }
        return $wrappers;
    }

    private function getWrappers(?string $componentId, ?string $projectId, ?string $configurationId): array
    {
        $wrappers = [];
        if ($this->encryptorOptions->getAkvUrl()) {
            $wrappers = array_merge($wrappers, $this->getAKVWrappers($componentId, $projectId, $configurationId));
        }

        if ($this->encryptorOptions->getKmsKeyRegion() && $this->encryptorOptions->getKmsKeyId()) {
            $wrappers = array_merge($wrappers, $this->getKMSWrappers($componentId, $projectId, $configurationId));
        }
        return $wrappers;
    }
}
