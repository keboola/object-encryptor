<?php

namespace Keboola\ObjectEncryptor\Exception;

class ApplicationException extends \Exception
{
    public function __construct($message, $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
