<?php

namespace Afk11\Pkcs5\Cipher\Aes;

class AesFactory
{
    const NAME_AES128CBC = 'aes-128-cbc';
    const NAME_AES192CBC = 'aes-192-cbc';
    const NAME_AES256CBC = 'aes-256-cbc';

    /**
     * @param int $length
     * @return AesParams
     */
    private function makeAes($length)
    {
        return new AesParams(random_bytes(openssl_cipher_iv_length("aes-$length-cbc")), $length);
    }

    /**
     * @return AesParams
     */
    public function aes128()
    {
        return $this->makeAes(128);
    }

    /**
     * @return AesParams
     */
    public function aes192()
    {
        return $this->makeAes(192);
    }

    /**
     * @return AesParams
     */
    public function aes256()
    {
        return $this->makeAes(256);
    }
}
