<?php

namespace Afk11\Pkcs5\Serializer;

use Afk11\Pkcs5\Cipher\Aes\AesParams;
use Afk11\Pkcs5\Cipher\CipherParamsInterface;
use Afk11\Pkcs5\Digest\DigestParamsInterface;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Params;
use Afk11\Pkcs5\Serializer\Cipher\Aes\AesParamsSerializer;
use Afk11\Pkcs5\Serializer\Digest\Params\Pbkdf2ParamsSerializer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\Sequence;

/**
 * Class Pkcs5v2Serializer
 * https://www.ietf.org/rfc/rfc2898.txt
 * @package Afk11\EcSSH\Pkcs5\Serializer
 */
class Pkcs5v2Serializer
{
    const OID = '1.2.840.113549.1.5.13';

    /**
     * @var Pbkdf2ParamsSerializer
     */
    private $pbkdf2ParamsSerializer;

    /**
     * @var AesParamsSerializer
     */
    private $aesParamsSerializer;

    public function __construct()
    {
        $this->pbkdf2ParamsSerializer = new Pbkdf2ParamsSerializer();
        $this->aesParamsSerializer = new AesParamsSerializer();
    }

    /**
     * @param DigestParamsInterface $digestParams
     * @return Sequence
     */
    private function getDigestParamsAsn(DigestParamsInterface $digestParams)
    {
        if ($digestParams instanceof Pbkdf2Params) {
            return $this->pbkdf2ParamsSerializer->serialize($digestParams);
        }

        throw new \RuntimeException('Unsupported digest algorithm');
    }

    /**
     * @param CipherParamsInterface $cipherParams
     * @return Sequence
     */
    private function getCipherParamsAsn(CipherParamsInterface $cipherParams)
    {
        if ($cipherParams instanceof AesParams) {
            return $this->aesParamsSerializer->serialize($cipherParams);
        }

        throw new \RuntimeException('Unsupported cipher algorithm');
    }
    
    /**
     * @param DigestParamsInterface $digestParams
     * @param CipherParamsInterface $cipherParams
     * @return Sequence
     */
    public function getPkcs5Data(DigestParamsInterface $digestParams, CipherParamsInterface $cipherParams)
    {
        return new Sequence(
            new ObjectIdentifier(self::OID),
            new Sequence(
                $this->getDigestParamsAsn($digestParams),
                $this->getCipherParamsAsn($cipherParams)
            )
        );
    }

    /**
     * @param DigestParamsInterface $digestParams
     * @param CipherParamsInterface $cipherParams
     * @return string
     */
    public function serialize(DigestParamsInterface $digestParams, CipherParamsInterface $cipherParams)
    {
        return $this->getPkcs5Data($digestParams, $cipherParams)->getBinary();
    }
}
