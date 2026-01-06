<?php

declare(strict_types=1);

namespace Kerattila\X509Auth\Certificate;

use Illuminate\Http\Request;

/**
 * Class ClientCertificate
 */
class ClientCertificate
{
    /**
     * Possible Certificate keys
     *
     * @var string[]
     */
    protected $keys = [
        'SSL_CLIENT_I_DN', // Certificate subject - Root CA
        'SSL_CLIENT_I_DN_CN', // Common name - Root CA
        'SSL_CLIENT_I_DN_O', // Organization - Root CA
        'SSL_CLIENT_I_DN_L', // Location - Root CA
        'SSL_CLIENT_I_DN_ST', // State - Root CA
        'SSL_CLIENT_I_DN_C', // Country (2 letter) - Root CA

        'SSL_CLIENT_CERT_RFC4523_CEA',
        'SSL_CLIENT_A_SIG',
        'SSL_CLIENT_A_KEY',
        'SSL_CLIENT_S_DN', // Certificate subject
        'SSL_CLIENT_V_REMAIN',
        'SSL_CLIENT_V_END', // Expire date
        'SSL_CLIENT_V_START', // Valability start date
        'SSL_CLIENT_M_SERIAL', // Certificate serial
        'SSL_CLIENT_M_VERSION',
        /**
         * NONE: client has no cert
         * SUCCESS = cert is valid
         * GENEROUS = says only that some kind of certificate was sent at all
         * FAILED:reason = auth with the cert failed
         */
        'SSL_CLIENT_VERIFY',
        'SSL_CLIENT_SAN_DNS_0', // Subject alternative names (in array, can be matched with SSL_SERVER_SAN_DNS_0
        'SSL_CLIENT_S_DN_Email', // Email
        'SSL_CLIENT_S_DN_CN', // Common name
        'SSL_CLIENT_S_DN_OU', // Organization Unit
        'SSL_CLIENT_S_DN_O', // Organization
        'SSL_CLIENT_S_DN_L', // Location
        'SSL_CLIENT_S_DN_ST', // State
        'SSL_CLIENT_S_DN_C', // Country (2 letter)
    ];

    /**
     * @var bool
     */
    public ?string $SSL_CLIENT_VERIFY = 'NONE';

    public ?string $SSL_CLIENT_M_SERIAL = null;

    public ?string $SSL_CLIENT_S_DN_Email = null;

    /**
     * ClientCertificate constructor.
     */
    public function __construct(Request $request)
    {
        foreach ($this->keys as $key) {
            if ($value = $request->server($key)) {
                $this->$key = $value;
            }
        }
    }

    public function get($key): ?string
    {
        if (in_array($key, $this->keys)) {
            return $this->$key;
        }

        return null;
    }

    public function has($key): bool
    {
        if (in_array($key, $this->keys)) {
            return isset($this->$key);
        }

        return false;
    }

    public function isValid(): bool
    {
        return $this->SSL_CLIENT_VERIFY === 'SUCCESS';
    }

    public function getSerial(): ?string
    {
        return $this->SSL_CLIENT_M_SERIAL;
    }

    public function getEmail(): ?string
    {
        return $this->SSL_CLIENT_S_DN_Email;
    }
}
