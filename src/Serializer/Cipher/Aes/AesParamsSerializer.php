<?php

namespace Afk11\Pkcs5\Serializer\Cipher\Aes;

use Afk11\Pkcs5\Cipher\Aes\AesParams;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Mdanter\Ecc\Serializer\Util\CipherOidMapper;

class AesParamsSerializer
{
    /**
     * @param AesParams $params
     * @return Sequence
     */
    public function serialize(AesParams $params)
    {
        return new Sequence(
            new ObjectIdentifier(CipherOidMapper::getCipherOid($params)),
            new OctetString(unpack("H*", $params->getIv())[1])
        );
    }
}
