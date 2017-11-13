<?php

namespace Keboola\ObjectEncryptor\Exception;

class UserException extends \Exception
{
    public function __construct($message, $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
