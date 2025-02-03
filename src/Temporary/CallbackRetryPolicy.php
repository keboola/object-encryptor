<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Temporary;

use Closure;
use Retry\Policy\SimpleRetryPolicy;
use Retry\RetryContextInterface;

class CallbackRetryPolicy extends SimpleRetryPolicy
{
    private Closure $shouldRetryCallback;

    public function __construct(
        callable $shouldRetryCallback,
        int $maxAttempts = 3,
    ) {
        parent::__construct($maxAttempts);
        $this->shouldRetryCallback = $shouldRetryCallback(...);
    }

    public function canRetry(RetryContextInterface $context): bool
    {
        $e = $context->getLastException();

        if (($this->shouldRetryCallback)($e, $context) !== true) {
            return false;
        }

        return parent::canRetry($context);
    }
}
