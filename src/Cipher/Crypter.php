<?php

namespace Afk11\Pkcs5\Cipher;

use Afk11\Pkcs5\Cipher\Aes\AesCrypt;
use Afk11\Pkcs5\Cipher\Aes\AesParams;

class Crypter
{
    /**
     * @var AesCrypt
     */
    private $aes;
    
    public function __construct()
    {
        $this->aes = new AesCrypt();
    }

    /**
     * @param string $data
     * @param string $key
     * @param CipherParamsInterface $cipherParams
     * @return string
     */
    public function encrypt($data, $key, CipherParamsInterface $cipherParams)
    {
        if ($cipherParams instanceof AesParams) {
            return $this->aes->encrypt($data, $key, $cipherParams);
        }

        throw new \RuntimeException('Unknown or unsupported cipher');
    }

    /**
     * @param string $data
     * @param string $key
     * @param CipherParamsInterface $cipherParams
     * @return string
     */
    public function decrypt($data, $key, CipherParamsInterface $cipherParams)
    {
        if ($cipherParams instanceof AesParams) {
            return $this->aes->decrypt($data, $key, $cipherParams);
        }

        throw new \RuntimeException('Unknown or unsupported cipher');
    }
}
