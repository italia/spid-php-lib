<?php

declare(strict_types=1);

namespace Italia\Spid\Spid\Exceptions;

use Exception;
use Throwable;

class SpidException extends Exception
{
    private $context;

    public function __construct($message = "", $code = 0, ?Throwable $previous = null, $context = null)
    {
        parent::__construct($message, $code, $previous);
        $this->context = $context;
    }

    public function getContext()
    {
        return $this->context;
    }
}
