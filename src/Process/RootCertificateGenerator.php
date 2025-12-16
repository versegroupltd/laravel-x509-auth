<?php

declare(strict_types=1);

namespace Kerattila\X509Auth\Process;

/**
 * Class RootCertificateGenerator
 */
class RootCertificateGenerator extends AbstractCertificateGeneratorProcess
{
    /**
     * RootCertificateGenerator constructor.
     */
    public function __construct(
        string $outputDir,
        string $privateKeyName = 'root_ca_private',
        string $publicKeyName = 'root_ca_public',
        array $subject = [],
        int $numbits = 2048,
        int $days = 30
    ) {
        parent::__construct(
            $outputDir,
            $privateKeyName,
            $publicKeyName,
            $subject,
            $numbits,
            $days
        );
    }

    /**
     * @throws \Kerattila\X509Auth\Exceptions\OpensslException
     */
    public function generate(bool $verbose = false): void
    {
        $this->generatePrivateKey($verbose);
        $this->generatePublicKey($verbose);
    }

    /**
     * @throws \Kerattila\X509Auth\Exceptions\OpensslException
     */
    protected function generatePrivateKey(bool $verbose = false): void
    {
        $this->runProcess([
            'openssl',
            'genrsa',
            '-out',
            $this->privateKeyPath,
            $this->numbits,
        ], $verbose);
    }

    /**
     * @throws \Kerattila\X509Auth\Exceptions\OpensslException
     */
    protected function generatePublicKey(bool $verbose = false): void
    {
        $this->runProcess([
            'openssl',
            'req',
            '-x509',
            '-new',
            '-nodes',
            '-key', $this->privateKeyPath,
            '-days', $this->days,
            '-out', $this->publicKeyPath,
            '-subj', $this->arrayToSubjectString($this->subject),
        ], $verbose);
    }
}
