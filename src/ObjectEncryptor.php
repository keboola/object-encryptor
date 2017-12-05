<?php

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Legacy\Encryptor;
use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;
use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;

class ObjectEncryptor
{
    /**
     * List of known wrappers.
     * @var CryptoWrapperInterface[]
     */
    private $wrappers = [];

    /**
     * Encryptor used only for decrypting legacy cipher texts.
     * @var Encryptor|null
     */
    private $legacyEncryptor = null;


    /**
     * ObjectEncryptor constructor.
     * @param Encryptor|null $legacyEncryptor Optional legacy decryptor.
     */
    public function __construct(Encryptor $legacyEncryptor = null)
    {
        $this->legacyEncryptor = $legacyEncryptor;
    }

    /**
     * @param string|array|\stdClass $data Data to encrypt
     * @param string $wrapperName Class name of encryptor wrapper
     * @return mixed
     * @throws ApplicationException
     */
    public function encrypt($data, $wrapperName = BaseWrapper::class)
    {
        /** @var BaseWrapper $wrapper */
        foreach ($this->wrappers as $cryptoWrapper) {
            if (get_class($cryptoWrapper) == $wrapperName) {
                $wrapper = $cryptoWrapper;
                break;
            }
        }
        if (empty($wrapper)) {
            throw new ApplicationException('Invalid crypto wrapper ' . $wrapperName);
        }
        if (is_scalar($data)) {
            return $this->encryptValue($data, $wrapper);
        }
        if (is_array($data)) {
            return $this->encryptArray($data, $wrapper);
        }
        if (is_object($data) && get_class($data) == \stdClass::class) {
            return $this->encryptObject($data, $wrapper);
        }
        throw new ApplicationException('Only stdClass, array and string are supported types for encryption.');
    }

    /**
     * @param mixed $data
     * @return mixed
     * @throws ApplicationException
     * @throws UserException
     */
    public function decrypt($data)
    {
        if (is_scalar($data)) {
            try {
                return $this->decryptValue($data);
            } catch (\InvalidCiphertextException $e) {
                throw new UserException($e->getMessage(), $e);
            }
        }
        if (is_array($data)) {
            return $this->decryptArray($data);
        }
        if (is_object($data) && get_class($data) == \stdClass::class) {
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

    /**
     * Find a wrapper to decrypt a given cipher.
     * @param string $value Cipher text
     * @return CryptoWrapperInterface|null
     * @throws ApplicationException
     */
    protected function findWrapper($value)
    {
        $selectedWrapper = null;
        if (empty($this->wrappers)) {
            throw new ApplicationException('There are no wrappers registered for the encryptor.');
        }
        foreach ($this->wrappers as $wrapper) {
            if (substr($value, 0, mb_strlen($wrapper->getPrefix())) == $wrapper->getPrefix()) {
                $selectedWrapper = $wrapper;
            }
        }
        return $selectedWrapper;
    }

    private function decryptLegacy($value)
    {
        /* @ is intentional to suppress warnings from invalid cipher texts which
        are handled by checking return === false */
        $ret = @$this->legacyEncryptor->decrypt($value);
        if ($ret === false) {
            throw new UserException('Value is not an encrypted value.');
        } else {
            return $ret;
        }
    }

    /**
     * @param $value
     * @return string
     * @throws ApplicationException
     * @throws UserException
     */
    protected function decryptValue($value)
    {
        $wrapper = $this->findWrapper($value);
        if (!$wrapper) {
            if ($this->legacyEncryptor) {
                return $this->decryptLegacy($value);
            } else {
                throw new UserException('Value is not an encrypted value.');
            }
        }
        try {
            return $wrapper->decrypt(substr($value, mb_strlen($wrapper->getPrefix())));
        } catch (\InvalidCiphertextException $e) {
            // this is for legacy wrappers
            throw new UserException("Value $value is not an encrypted value.");
        } catch (UserException $e) {
            throw new UserException("Value $value is not an encrypted value.");
        } catch (\Exception $e) {
            // decryption failed for more serious reasons
            throw new ApplicationException('Decryption failed: ' . $e->getMessage(), $e);
        }
    }

    /**
     * @param $key
     * @param $value
     * @param CryptoWrapperInterface $wrapper
     * @return array|string
     * @throws ApplicationException
     */
    protected function encryptItem($key, $value, CryptoWrapperInterface $wrapper)
    {
        if (is_scalar($value) || is_null($value)) {
            if (substr($key, 0, 1) == '#') {
                return $this->encryptValue($value, $wrapper);
            } else {
                return $value;
            }
        } elseif (is_array($value)) {
            return $this->encryptArray($value, $wrapper);
        } elseif (is_object($value) && get_class($value) == \stdClass::class) {
            return $this->encryptObject($value, $wrapper);
        } else {
            throw new ApplicationException(
                'Invalid item $key - only stdClass, array and scalar can be encrypted.'
            );
        }
    }

    /**
     * @param string $value Value to encrypt.
     * @param CryptoWrapperInterface $wrapper Ciphering wrapper.
     * @return string Encrypted value.
     * @throws ApplicationException
     */
    protected function encryptValue($value, CryptoWrapperInterface $wrapper)
    {
        // return self if already encrypted with any wrapper
        if ($this->findWrapper($value)) {
            return $value;
        }

        try {
            return $wrapper->getPrefix() . $wrapper->encrypt($value);
        } catch (\Exception $e) {
            throw new ApplicationException('Encryption failed: ' . $e->getMessage(), $e);
        }
    }

    /**
     * @param array $data
     * @param CryptoWrapperInterface $wrapper
     * @return array
     * @throws ApplicationException
     */
    protected function encryptArray(array $data, CryptoWrapperInterface $wrapper)
    {
        $result = [];
        foreach ($data as $key => $value) {
            $result[$key] = $this->encryptItem($key, $value, $wrapper);
        }
        return $result;
    }

    /**
     * @param \stdClass $data
     * @param CryptoWrapperInterface $wrapper
     * @return \stdClass
     * @throws ApplicationException
     */
    protected function encryptObject(\stdClass $data, CryptoWrapperInterface $wrapper)
    {
        $result = new \stdClass();
        foreach (get_object_vars($data) as $key => $value) {
            $result->{$key} = $this->encryptItem($key, $value, $wrapper);
        }
        return $result;
    }

    /**
     * @param $key
     * @param $value
     * @return array|string
     * @throws ApplicationException
     * @throws UserException
     */
    protected function decryptItem($key, $value)
    {
        try {
            if (is_scalar($value) || is_null($value)) {
                if (substr($key, 0, 1) == '#') {
                    return $this->decryptValue($value);
                } else {
                    return $value;
                }
            } elseif (is_array($value)) {
                return $this->decryptArray($value);
            } elseif (is_object($value) && get_class($value) == \stdClass::class) {
                return $this->decryptObject($value);
            } else {
                throw new ApplicationException(
                    "Invalid item $key - only stdClass, array and scalar can be decrypted."
                );
            }
        } catch (UserException $e) {
            throw new UserException("Invalid cipher text for key $key " . $e->getMessage(), $e);
        }
    }

    /**
     * @param \stdClass $data
     * @return \stdClass
     * @throws ApplicationException
     * @throws UserException
     */
    protected function decryptObject(\stdClass $data)
    {
        $result = new \stdClass();
        foreach (get_object_vars($data) as $key => $value) {
            $result->{$key} = $this->decryptItem($key, $value);
        }
        return $result;
    }

    /**
     * @param array $data
     * @return array
     * @throws ApplicationException
     * @throws UserException
     */
    protected function decryptArray(array $data)
    {
        $result = [];
        foreach ($data as $key => $value) {
            $result[$key] = $this->decryptItem($key, $value);
        }
        return $result;
    }
}
