<?php

namespace Afk11\Pkcs5\Cipher;

use Afk11\Pkcs5\Cipher\Aes\AesFactory;
use Afk11\Pkcs5\Cipher\Aes\AesParams;

class CipherFactory
{
    /**
     * @return AesFactory
     */
    public static function getAesFactory()
    {
        return new AesFactory();
    }

    /**
     * @param string $name
     * @return AesParams
     */
    public static function generateParamsByName($name)
    {
        $aesFactory = self::getAesFactory();

        switch ($name) {
            case AesFactory::NAME_AES128CBC:
                return $aesFactory->aes128();
            case AesFactory::NAME_AES192CBC:
                return $aesFactory->aes192();
            case AesFactory::NAME_AES256CBC:
                return $aesFactory->aes256();
            default:
                throw new \RuntimeException('Unknown or unsupported cipher.');
        }
    }
}
