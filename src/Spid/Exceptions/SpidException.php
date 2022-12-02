<?php
declare(strict_types=1);

namespace Italia\Spid\Spid\Exceptions;

class SpidException extends \Exception
{
    private ?string $contextData;

    public function __construct(string $message = "", ?string $contextData = null, int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->contextData = $contextData;
    }

    /**
     * @return ?string
     */
    public function getContextData(): ?string
    {
        return $this->contextData;
    }
}