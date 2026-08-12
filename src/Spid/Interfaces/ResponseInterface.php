<?php

namespace Italia\Spid\Spid\Interfaces;

interface ResponseInterface
{
    // Validates a received response.
    // $assertion is the <saml:Assertion> element whose signature has just been
    // validated, or null for messages that carry no assertion. Identity data must
    // be read from that element only, never from the document at large.
    // Throws exceptions on missing or invalid values.
    // returns false if resposne code is not success
    // returns true otherwise
    public function validate($xml, $assertion) : bool;
}
