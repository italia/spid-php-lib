<?php

use Italia\Spid\Spid\Exceptions\SpidException;
use Italia\Spid\Spid\Interfaces\LoggerSelector;

class LoggerMock implements LoggerSelector
{

    public function getPermanentLogger(): ?\Psr\Log\LoggerInterface
    {
        return null;
    }

    public function getTemporaryLogger(): ?\Psr\Log\LoggerInterface
    {
        return null;
    }

    public function logAndThrow(\DOMDocument $xml, $message): void
    {
        throw new SpidException();
    }
}