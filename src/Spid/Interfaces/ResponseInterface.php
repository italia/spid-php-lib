<?php

namespace Italia\Spid\Spid\Interfaces;

interface ResponseInterface
{
    // Validates a received response.
    // Throws exceptions on missing or invalid values.
    // returns false if resposne code is not success
    // returns true otherwise
    public function validate($xml, $hasAssertion) : bool;
}
