<?php

namespace Mdanter\Ecc\Serializer\Util;

use Afk11\Pkcs5\Digest\DigestParamsInterface;
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
     * @param DigestParamsInterface $params
     * @return ObjectIdentifier
     */
    public static function getDigestOid(DigestParamsInterface $params)
    {
        if (array_key_exists($params->getMethod(), self::$oidMap)) {
            $oidString = self::$oidMap[$params->getMethod()];

            return new ObjectIdentifier($oidString);
        }

        throw new \RuntimeException('Unsupported cipher type.');
    }

    /**
     * @param ObjectIdentifier $oid
     * @return \Mdanter\Ecc\Primitives\GeneratorPoint
     */
    public static function getCipherFromOid(ObjectIdentifier $oid)
    {
        $oidString = $oid->getContent();
        $invertedMap = array_flip(self::$oidMap);

        if (array_key_exists($oidString, $invertedMap)) {
            return $invertedMap[$oidString];
        }

        throw new \RuntimeException('Invalid data: unsupported cipher');
    }
}
