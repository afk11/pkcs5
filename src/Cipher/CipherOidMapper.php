<?php

namespace Afk11\Pkcs5\Cipher;

use Afk11\Pkcs5\Cipher\Aes\AesFactory;
use FG\ASN1\Universal\ObjectIdentifier;

class CipherOidMapper
{

    const AES_128_CBC = '2.16.840.1.101.3.4.1.2';
    const AES_192_CBC = '2.16.840.1.101.3.4.1.22';
    const AES_256_CBC = '2.16.840.1.101.3.4.1.42';

    /**
     * @var array
     */
    private static $oidMap = array(
        AesFactory::NAME_AES128CBC => self::AES_128_CBC,
        AesFactory::NAME_AES192CBC => self::AES_192_CBC,
        AesFactory::NAME_AES256CBC => self::AES_256_CBC
    );

    /**
     * @return array
     */
    public static function getNames()
    {
        return array_keys(self::$oidMap);
    }

    /**
     * @param CipherParamsInterface $params
     * @return ObjectIdentifier
     */
    public static function getCipherOid(CipherParamsInterface $params)
    {
        if (array_key_exists($params->getName(), self::$oidMap)) {
            $oidString = self::$oidMap[$params->getName()];

            return new ObjectIdentifier($oidString);
        }

        throw new \RuntimeException('Unsupported cipher type.');
    }

    /**
     * @param ObjectIdentifier $oid
     * @return string
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
