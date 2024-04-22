<?php

declare(strict_types=1);

namespace Italia\Spid\Spid\Interfaces;

use DOMDocument;
use Italia\Spid\Spid\Exceptions\SpidException;
use Psr\Log\LoggerInterface;

interface LoggerSelector
{
    public function getPermanentLogger(): ?LoggerInterface;
    public function getTemporaryLogger(): ?LoggerInterface;

    /**
     * @param DOMDocument $xml
     * @param $message
     * @return never
     * @throws SpidException
     */
    public function logAndThrow(DOMDocument $xml, $message): void;
}
