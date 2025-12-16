<?php

declare(strict_types=1);

namespace Kerattila\X509Auth\Process;

use Kerattila\X509Auth\Exceptions\OpensslException;

/**
 * Class SignedCertificateGenerator
 */
class SignedCertificateGenerator extends AbstractCertificateGeneratorProcess
{
    protected string $fullChainPath;

    protected string $pkcs12Path;

    protected string $csrPath;

    protected string $rootCaPrivateKeyPath;

    protected string $rootCaPublicKeyPath;

    protected array $tempFiles = [];

    /**
     * SignedCertificateGenerator constructor.
     */
    public function __construct(
        string $outputDir,
        protected string $rootCaPrivateKeyName,
        protected string $rootCaPublicKeyName,
        protected string $pkcs12Password,
        string $privateKeyName = 'private',
        string $publicKeyName = 'public',
        protected string $csrName = 'csr',
        array $subject = [],
        protected array $altNames = [],
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
        $this->csrPath = $this->buildPathTo("{$this->csrName}.pem");

        $this->fullChainPath = $this->buildPathTo("$privateKeyName-fullchain.pem");
        $this->pkcs12Path = $this->buildPathTo("$privateKeyName.pfx");
        $this->rootCaPrivateKeyPath = $this->buildPathTo($this->rootCaPrivateKeyName);
        $this->rootCaPublicKeyPath = $this->buildPathTo($this->rootCaPublicKeyName);
    }

    public function generate(bool $verbose = false): void
    {
        $this->generatePrivateKey($verbose);
        $this->generateCSR($verbose);
        $this->generatePublicKey($verbose);
        $this->buildFullChainCertificate(
            $this->publicKeyPath,
            $this->rootCaPublicKeyPath
        );
        $this->generatePKCS12Certificate($verbose);

        $this->cleanupFiles(
            ...$this->tempFiles
        );
    }

    /**
     * @throws OpensslException
     */
    public function generatePrivateKey(bool $verbose): void
    {
        $this->runProcess([
            'openssl', 'genrsa', '-out', $this->privateKeyPath,
        ], $verbose);
    }

    /**
     * @throws OpensslException
     */
    public function generateCSR(bool $verbose): void
    {
        $configFilePath = $this->generateConfigFile();
        $this->runProcess([
            'openssl',
            'req',
            '-new',
            '-key', $this->privateKeyPath,
            '-out', $this->csrPath,
            '-in', $this->csrPath,
            '-subj', $this->arrayToSubjectString($this->subject),
            '-config', $configFilePath,
        ], $verbose);
        $this->tempFiles[] = $this->csrPath;
        $this->tempFiles[] = $configFilePath;
    }

    /**
     * @throws OpensslException
     */
    public function generatePublicKey(bool $verbose): void
    {
        $v3ConfigFilePath = $this->generateV3ConfigFile();
        $this->runProcess([
            'openssl',
            'x509',
            '-req',
            '-in', $this->csrPath,
            '-CA', $this->rootCaPublicKeyPath,
            '-CAkey', $this->rootCaPrivateKeyPath,
            '-CAcreateserial',
            '-out', $this->publicKeyPath,
            '-days', $this->days,
            '-sha256',
            '-extfile', $v3ConfigFilePath,
        ], $verbose);
        $this->tempFiles[] = $v3ConfigFilePath;
    }

    /**
     * @throws OpensslException
     */
    protected function generatePKCS12Certificate(bool $verbose): void
    {
        $this->runProcess([
            'openssl',
            'pkcs12',
            '-export',
            '-out', $this->pkcs12Path,
            '-inkey', $this->privateKeyPath,
            '-in', $this->fullChainPath,
            '-certfile', $this->rootCaPrivateKeyPath,
            '-passout', 'pass:'.$this->pkcs12Password,
        ], $verbose);
    }

    protected function generateConfigFile(): string
    {
        $configFileName = $this->buildPathTo(time().'.cnf');
        $configData = <<<CONFIG
[req]
default_bits = 4096
prompt = no
encrypt_key = no
default_md = sha256
distinguished_name = distinguished_name
req_extensions = req_ext

[distinguished_name]
CN = {$this->subject['CN']}
emailAddress = {$this->subject['emailAddress']}
O = {$this->subject['O']}
OU = {$this->subject['OU']}
L = {$this->subject['L']}
ST = {$this->subject['ST']}
C = {$this->subject['C']}

[req_ext]
subjectAltName = @alt_names

[alt_names]
CONFIG;
        if (count($this->altNames)) {
            foreach ($this->altNames as $i => $altName) {
                $configData .= "\nDNS.".($i + 1)." = $altName";
            }
        }
        file_put_contents($configFileName, $configData);

        return $configFileName;
    }

    protected function generateV3ConfigFile(): string
    {
        $configFileName = $this->buildPathTo(time().'.cnf');
        $configData = <<<'CONFIG'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
CONFIG;
        if (count($this->altNames)) {
            foreach ($this->altNames as $i => $altName) {
                $configData .= "\nDNS.".($i + 1)." = $altName";
            }
        }
        file_put_contents($configFileName, $configData);

        return $configFileName;
    }

    protected function buildFullChainCertificate()
    {
        $files = func_get_args();
        foreach ($files as $file) {
            if (! file_exists($file)) {
                throw new \LogicException("Full chain generation failed. \"$file\" not found.");
            }
            file_put_contents(
                $this->fullChainPath,
                file_get_contents($file),
                FILE_APPEND
            );
        }
    }

    protected function cleanupFiles(): void
    {
        $files = func_get_args();
        foreach ($files as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }
}
