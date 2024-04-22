<?php

namespace Italia\Spid\Spid;

class Session
{
    public $sessionID; // Unique session Id string
    public $idp; // Idp object
    public $idpEntityID;
    public $level; // Login level (1,2,3)
    public $attributes; // array, requested user attributes during login. attribute name -> value

    public function __construct(array $values = null)
    {
        if (is_null($values)) {
            return;
        }
        foreach ($values as $key => $value) {
            if (property_exists($this, $key)) {
                $this->{$key} =  $value;
            }
        }
    }

    public function isValid(): bool
    {
        if (
            empty($this->sessionID) ||
            empty($this->idp) ||
            empty($this->idpEntityID) ||
            empty($this->level)
        ) {
            return false;
        }
        return true;
    }
}
