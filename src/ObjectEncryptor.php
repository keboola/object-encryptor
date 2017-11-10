<?php

namespace Keboola\ObjectEncryptor;

use Keboola\Syrup\Encryption\BaseWrapper;
use Keboola\Syrup\Encryption\CryptoWrapperInterface;
use Keboola\Syrup\Encryption\Encryptor;
use Keboola\Syrup\Exception\ApplicationException;
use Keboola\Syrup\Exception\UserException;

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
            throw new ApplicationException("Invalid crypto wrapper " . $wrapperName);
        }
        if (is_scalar($data)) {
            return $this->encryptValue($data, $wrapper);
        }
        if (is_array($data)) {
            return $this->encryptArray($data, $wrapper);
        }
        if (is_object($data) && get_class($data) == 'stdClass') {
            return $this->encryptObject($data, $wrapper);
        }
        throw new ApplicationException("Only stdClass, array and string are supported types for encryption.");
    }

    /**
     * @param mixed $data
     * @return mixed
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
        if (is_object($data) && get_class($data) == 'stdClass') {
            return $this->decryptObject($data);
        }
        throw new ApplicationException("Only stdClass, array and string are supported types for decryption.");
    }

    /**
     * Manually add a known crypto wrapper. Generally, wrappers should be added to services.yml with tag
     * 'syrup.encryption.wrapper' - that way, they will be added automatically.
     * @param CryptoWrapperInterface $wrapper
     */
    public function pushWrapper(CryptoWrapperInterface $wrapper)
    {
        if (isset($this->wrappers[$wrapper->getPrefix()])) {
            throw new ApplicationException("Cryptowrapper prefix " . $wrapper->getPrefix() . " is not unique.");
        }
        $this->wrappers[$wrapper->getPrefix()] = $wrapper;
    }

    /**
     * Find a wrapper to decrypt a given cipher.
     * @param string $value Cipher text
     * @return CryptoWrapperInterface|null
     */
    protected function findWrapper($value)
    {
        $selectedWrapper = null;
        if (empty($this->wrappers)) {
            throw new ApplicationException("There are no wrappers registered for the encryptor.");
        }
        foreach ($this->wrappers as $wrapper) {
            if (substr($value, 0, mb_strlen($wrapper->getPrefix())) == $wrapper->getPrefix()) {
                $selectedWrapper = $wrapper;
            }
        }
        return $selectedWrapper;
    }

    /**
     * @param $value
     * @return string
     * @throws \InvalidCiphertextException
     */
    protected function decryptValue($value)
    {
        $wrapper = $this->findWrapper($value);
        if (!$wrapper) {
            if ($this->legacyEncryptor) {
                /* @ is intentional to suppress warnings from invalid cipher texts which
                 are handled by checking return === false */
                $ret = @$this->legacyEncryptor->decrypt($value);
                if ($ret === false) {
                    throw new \InvalidCiphertextException("Value is not an encrypted value.");
                } else {
                    return $ret;
                }
            } else {
                throw new \InvalidCiphertextException("Value is not an encrypted value.");
            }
        }
        try {
            return $wrapper->decrypt(substr($value, mb_strlen($wrapper->getPrefix())));
        } catch (\InvalidCiphertextException $e) {
            throw new \InvalidCiphertextException("Value $value is not an encrypted value.");
        } catch (\Exception $e) {
            // decryption failed for more serious reasons
            throw new ApplicationException("Decryption failed: " . $e->getMessage(), $e, ["value" => $value]);
        }
    }

    /**
     * @param $key
     * @param $value
     * @param CryptoWrapperInterface $wrapper
     * @return array|string|void
     */
    protected function encryptItem($key, $value, CryptoWrapperInterface $wrapper)
    {
        $result = null;
        if (substr($key, 0, 1) == '#') {
            if (is_scalar($value) || is_null($value)) {
                return $this->encryptValue($value, $wrapper);
            } elseif (is_array($value)) {
                return $this->encryptArray($value, $wrapper);
            } elseif (is_object($value) && get_class($value) == 'stdClass') {
                return $this->encryptObject($value, $wrapper);
            } else {
                throw new ApplicationException(
                    "Invalid item $key - only stdClass, array and scalar can be encrypted."
                );
            }
        } else {
            if (is_scalar($value) || is_null($value)) {
                return $value;
            } elseif (is_array($value)) {
                return $this->encryptArray($value, $wrapper);
            } elseif (is_object($value) && get_class($value) == 'stdClass') {
                return $this->encryptObject($value, $wrapper);
            } else {
                throw new ApplicationException(
                    "Invalid item $key - only stdClass, array and scalar can be encrypted."
                );
            }
        }
    }

    /**
     * @param string $value
     * @param CryptoWrapperInterface $wrapper
     * @return string
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
            throw new ApplicationException("Encryption failed: " . $e->getMessage(), $e, ["value" => $value]);
        }
    }

    /**
     * @param array $data
     * @param CryptoWrapperInterface $wrapper
     * @return array
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
     * @return array|string|void
     */
    protected function decryptItem($key, $value)
    {
        try {
            if (substr($key, 0, 1) == '#') {
                if (is_scalar($value)) {
                    return $this->decryptValue($value);
                } elseif (is_array($value)) {
                    return $this->decryptArray($value);
                } elseif (is_object($value) && get_class($value) == 'stdClass') {
                    return $this->decryptObject($value);
                } else {
                    throw new ApplicationException(
                        "Invalid item $key - only stdClass, array and scalar can be decrypted."
                    );
                }
            } else {
                if (is_scalar($value) || is_null($value)) {
                    return $value;
                } elseif (is_array($value)) {
                    return $this->decryptArray($value);
                } elseif (is_object($value) && get_class($value) == 'stdClass') {
                    return $this->decryptObject($value);
                } else {
                    throw new ApplicationException(
                        "Invalid item $key - only stdClass, array and scalar can be decrypted."
                    );
                }
            }
        } catch (\InvalidCiphertextException $e) {
            throw new UserException("Invalid cipher text for key $key " . $e->getMessage(), $e);
        }
    }

    /**
     * @param \stdClass $data
     * @return \stdClass
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
