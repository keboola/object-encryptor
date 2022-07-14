<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Exception;

use Keboola\CommonExceptions\ExceptionWithContextInterface;
use Keboola\CommonExceptions\UserExceptionInterface;
use RuntimeException;
use Throwable;

class UserException extends RuntimeException implements UserExceptionInterface, ExceptionWithContextInterface
{
    private array $context;

    public function __construct(string $message, int $code = 0, ?Throwable $previous = null, array $context = [])
    {
        parent::__construct($message, $code, $previous);
        $this->context = $context;
    }

    public function getContext(): array
    {
        return $this->context;
    }
}
