<?php

declare(strict_types=1);

namespace Kerattila\X509Auth\Process;

use Kerattila\X509Auth\Exceptions\OpensslException;
use Symfony\Component\Process\Process as SymfonyProcess;

/**
 * Class AbstractProcess
 */
abstract class AbstractProcess
{
    /**
     * @var string Output/working directory
     */
    protected string $outputdir;

    /**
     * @var string This is the full path for to the private key (incl. filename)
     */
    protected string $privateKeyPath;

    /**
     * @var string This is the full path for to the public key (incl. filename)
     */
    protected string $publicKeyPath;

    /**
     * AbstractProcess constructor.
     */
    public function __construct(
        string $outputDir,
        protected string $privateKeyName,
        protected string $publicKeyName
    ) {
        $this->checkOutputDir($outputDir);
        $this->outputdir = $outputDir;
        $this->privateKeyPath = $this->buildPathTo("$this->privateKeyName.key.pem");
        $this->publicKeyPath = $this->buildPathTo("$this->publicKeyName.crt.pem");

        return $this;
    }

    protected function buildPathTo(string $file): string
    {
        return rtrim($this->outputdir, '\/').DIRECTORY_SEPARATOR.$file;
    }

    protected function checkOutputDir(string $dir)
    {
        if (! is_dir($dir)) {
            throw new \LogicException('Output path is not a valid directory');
        }
    }

    /**
     * @throws OpensslException
     */
    protected function runProcess(array $params, bool $verbose = false): ?bool
    {
        $privateKeyProcess = (new SymfonyProcess($params));
        $privateKeyProcess->setTty(true);
        if (! $verbose) {
            $privateKeyProcess->disableOutput();
        }
        $exitCode = $privateKeyProcess->run();
        if ($exitCode === 0) {
            return true;
        } else {
            throw new OpensslException(
                'An error ocurred while running OpenSSL command. Try running process with verbose.'
            );
        }
    }

    abstract public function generate(bool $verbose = false): void;
}
