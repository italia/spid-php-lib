<?php

namespace Italia\Spid\Spid;

class Session
{
    public $sessionID; // Unique session Id string
    public $idp; // Idp object
    public $idpEntityID;
    public $level; // Login level (1,2,3)
    public $attributes; // array, requested user attributes during login. attribute name -> value
}
