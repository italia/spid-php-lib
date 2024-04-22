<?php

declare(strict_types=1);

namespace Italia\Spid\Spid\Logging;

use Italia\Spid\Spid\Exceptions\SpidException;
use Italia\Spid\Spid\Interfaces\LoggerSelector;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

abstract class AbstractLoggerSelector implements LoggerSelector
{
    public const WARNINGS = [
        19 => 'Autenticazione fallita per ripetuta sottomissione di credenziali errate',
        20 => 'Utente privo di credenziali compatibili con il livello richiesto dal fornitore del servizio',
        21 => "Timeout durante l'autenticazione dell'utente",
        22 => "Utente nega il consenso all'invio di dati al SP in caso di sessione vigente",
        23 => 'Utente con identità sospesa/revocata o con credenziali bloccate',
        25 => "Processo di autenticazione annullato dall'utente",
        30 => "Tentativo dell'utente di utilizzare una tipologia di identità digitale " .
              'diversa da quanto richiesto dal service provider'
    ];

    public const GENERIC_ERROR = 'Accesso temporaneamente non disponibile, si prega di riprovare.';

    abstract public function getPermanentLogger(): ?LoggerInterface;

    abstract public function getTemporaryLogger(): ?LoggerInterface;

    private function getErrorCodeFromXml(\DOMDocument $xml): int
    {
        $errorCode = -1;
        $statusMessage = $xml->getElementsByTagName('StatusMessage');
        if ($statusMessage->item(0) && $statusMessage->item(0)->nodeValue) {
            $errorString = $statusMessage->item(0)->nodeValue;
            $errorCode = intval(str_replace('ErrorCode nr', '', $errorString)) ?: -1;
        }
        return $errorCode;
    }

    public static function getErrorLevel(int $code): string
    {
        if (array_key_exists($code, self::WARNINGS)) {
            return LogLevel::WARNING;
        }
        return LogLevel::ERROR;
    }

    public static function getErrorMessage(int $code): string
    {
        if (array_key_exists($code, self::WARNINGS)) {
            return self::WARNINGS[$code];
        }
        return self::GENERIC_ERROR;
    }

    public function logAndThrow(\DOMDocument $xml, $message): void
    {
        $errorCode = self::getErrorCodeFromXml($xml);
        $xmlString = $xml->saveXML();
        $logger = $this->getPermanentLogger();
        if ($logger) {
            $logger->log(
                self::getErrorLevel($errorCode),
                $message,
                ['xml' => $xmlString, 'error_message' => self::getErrorMessage($errorCode)]
            );
        }
        throw new SpidException($message, $errorCode, null, $xmlString);
    }
}
