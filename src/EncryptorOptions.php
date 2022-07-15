<?php

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class EncryptorOptions
{
    private ?string $kmsKeyId;
    private ?string $kmsKeyRegion;
    private ?string $akvUrl;
    private string $stackId;

    public function __construct(string $stackId, ?string $kmsKeyId, ?string $kmsRegion, ?string $akvUrl)
    {
        $this->stackId = $stackId;
        $this->kmsKeyId = $kmsKeyId;
        $this->kmsKeyRegion = $kmsRegion;
        $this->akvUrl = $akvUrl;
    }

    public function getKmsKeyId(): ?string
    {
        return $this->kmsKeyId;
    }

    public function getKmsKeyRegion(): ?string
    {
        return $this->kmsKeyRegion;
    }

    public function getAkvUrl(): ?string
    {
        return $this->akvUrl;
    }

    public function getStackId(): string
    {
        return $this->stackId;
    }

    /**
     * @throws ApplicationException
     */
    private function validateState(): void
    {
        if (!is_null($this->kmsKeyId) && !is_string($this->kmsKeyId)) {
            throw new ApplicationException('Invalid KMS key Id.');
        }
        if (!is_null($this->kmsKeyRegion) && !is_string($this->kmsKeyRegion)) {
            throw new ApplicationException('Invalid KMS region.');
        }
        if (!is_null($this->akvUrl) && !is_string($this->akvUrl)) {
            throw new ApplicationException('Invalid AKV URL.');
        }
    }
}