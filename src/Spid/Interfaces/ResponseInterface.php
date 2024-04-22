<?php

declare(strict_types=1);

namespace Italia\Spid\Spid\Interfaces;

use DOMDocument;

interface ResponseInterface
{
    // Validates a received response.
    // Throws exceptions on missing or invalid values.
    // returns false if response code is not success
    // returns true otherwise
    public function validate(DOMDocument $xml, $hasAssertion): bool;
}
