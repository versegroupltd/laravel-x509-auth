<?php

declare(strict_types=1);

namespace Kerattila\X509Auth\Exceptions;

use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

/**
 * Class InvalidClientCertificateException
 */
class InvalidClientCertificateException extends UnauthorizedHttpException {}
