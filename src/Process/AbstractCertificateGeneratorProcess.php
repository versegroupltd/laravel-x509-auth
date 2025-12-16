<?php

declare(strict_types=1);

namespace Kerattila\X509Auth\Process;

/**
 * Class AbstractCertificateGeneratorProcess
 */
abstract class AbstractCertificateGeneratorProcess extends AbstractProcess
{
    /**
     * AbstractCertificateGeneratorProcess constructor.
     */
    public function __construct(
        string $outputDir,
        string $privateKeyName,
        string $publicKeyName,
        protected array $subject,
        protected int $numbits = 2048,
        protected int $days = 30
    ) {
        parent::__construct($outputDir, $privateKeyName, $publicKeyName);

        return $this;
    }

    protected function arrayToSubjectString(array $subject): string
    {
        $lines = array_map(fn ($key) => sprintf('%s=%s', $key, addslashes((string) $subject[$key])), array_keys($subject));
        if (! count($lines)) {
            return '';
        }

        return '/'.implode('/', $lines);
    }
}
