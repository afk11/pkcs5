<?php

namespace Afk11\Pkcs5\Digest\Pbkdf2;

class Pbkdf2Digest
{
    private static $mapToNative = [
        Pbkdf2Factory::HMAC_WITH_SHA1 => 'sha1',
        Pbkdf2Factory::PBKDF2_WITH_SHA224 => 'sha224',
        Pbkdf2Factory::PBKDF2_WITH_SHA256 => 'sha256',
        Pbkdf2Factory::PBKDF2_WITH_SHA384 => 'sha384',
        Pbkdf2Factory::PBKDF2_WITH_SHA512 => 'sha512'
    ];

    private function getPHPName($publicName)
    {
        if (!array_key_exists($publicName, self::$mapToNative)) {
            throw new \RuntimeException('Unknown algorithm');
        }

        return self::$mapToNative[$publicName];
    }

    /**
     * @param string $password
     * @param Pbkdf2Params $params
     * @return string
     */
    public function hash($password, Pbkdf2Params $params)
    {
        $keyLength = $params->getKeyLength();
        return hash_pbkdf2($this->getPHPName($params->getMethod()), $password, $params->getSalt(), $params->getIterationCount(), $keyLength, true);
    }
}
