<?php

namespace Afk11\Pkcs5\Digest\Pbkdf2;

class Pbkdf2AlgoOidMapper
{
    const HMAC_WITH_SHA1 = '1.2.840.113549.2.7';
    const PBKDF2_WITH_SHA224 = '1.2.840.113549.2.8';
    const PBKDF2_WITH_SHA256 = '1.2.840.113549.2.9';
    const PBKDF2_WITH_SHA384 = '1.2.840.113549.2.10';
    const PBKDF2_WITH_SHA512 = '1.2.840.113549.2.11';

    /**
     * @var array
     */
    private static $oidMap = array(
        Pbkdf2Factory::PBKDF2_WITH_SHA224 => self::PBKDF2_WITH_SHA224,
        Pbkdf2Factory::PBKDF2_WITH_SHA256 => self::PBKDF2_WITH_SHA256,
        Pbkdf2Factory::PBKDF2_WITH_SHA384 => self::PBKDF2_WITH_SHA384,
        Pbkdf2Factory::PBKDF2_WITH_SHA512 => self::PBKDF2_WITH_SHA512,
        Pbkdf2Factory::HMAC_WITH_SHA1 => self::HMAC_WITH_SHA1,
    );

    /**
     * @var array
     */
    private static $sizeMap = array(
        Pbkdf2Factory::PBKDF2_WITH_SHA224 => 160 / 8,
        Pbkdf2Factory::PBKDF2_WITH_SHA224 => 224 / 8,
        Pbkdf2Factory::PBKDF2_WITH_SHA256 => 256 / 8,
        Pbkdf2Factory::PBKDF2_WITH_SHA384 => 384 / 8,
        Pbkdf2Factory::PBKDF2_WITH_SHA512 => 512 / 8,
    );

    /**
     * @return array
     */
    public static function getNames()
    {
        return array_keys(self::$oidMap);
    }

    /**
     * @param string $name
     * @return array
     */
    public function getAlgoSizeByName($name)
    {
        if (!array_key_exists($name, self::$sizeMap)) {
            throw new \RuntimeException('Unknown or unsupported pbkdf2 algorithm');
        }

        return self::$sizeMap[$name];
    }

    /**
     * @param string $name
     * @return array
     */
    public static function getOidByName($name)
    {
        if (!array_key_exists($name, self::$oidMap)) {
            throw new \RuntimeException('Unknown or unsupported pbkdf2 algorithm');
        }

        return self::$oidMap[$name];
    }
}
