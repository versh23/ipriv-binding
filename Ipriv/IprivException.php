<?php

declare(strict_types=1);

namespace App\Ipriv;

use Throwable;

final class IprivException extends \Exception
{
    public function __construct($message = '', $code = 0, Throwable $previous = null)
    {
        parent::__construct(sprintf('%s. Код: %s', $message, $code), $code, $previous);
    }
}
