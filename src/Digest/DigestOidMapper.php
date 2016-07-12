<?php

namespace Afk11\Pkcs5\Digest\Pbkdf2;

use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Factory;
use FG\ASN1\Universal\ObjectIdentifier;

class DigestOidMapper
{

    const PKCS5PBKDF2 = '1.2.840.113549.1.5.12';

    /**
     * @var array
     */
    private static $oidMap = array(
        Pbkdf2Factory::NAME_PBKDF2 => self::PKCS5PBKDF2,
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
     * @return ObjectIdentifier
     */
    public static function getOidByName($name)
    {
        if (array_key_exists($name, self::$oidMap)) {
            $oidString = self::$oidMap[$name];

            return new ObjectIdentifier($oidString);
        }

        throw new \RuntimeException('Unsupported cipher type.');
    }

    /**
     * @param ObjectIdentifier $oid
     * @return \Mdanter\Ecc\Primitives\GeneratorPoint
     */
    public static function getNameByOid(ObjectIdentifier $oid)
    {
        $oidString = $oid->getContent();
        $invertedMap = array_flip(self::$oidMap);

        if (array_key_exists($oidString, $invertedMap)) {
            return $invertedMap[$oidString];
        }

        throw new \RuntimeException('Invalid data: unsupported cipher');
    }
}
