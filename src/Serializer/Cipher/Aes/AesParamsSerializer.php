<?php

namespace Afk11\Pkcs5\Serializer\Cipher\Aes;

use Afk11\Pkcs5\Cipher\Aes\AesParams;
use Afk11\Pkcs5\Cipher\CipherOidMapper;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;

class AesParamsSerializer
{
    /**
     * @param AesParams $params
     * @return Sequence
     */
    public function getAsn(AesParams $params)
    {
        return new Sequence(
            CipherOidMapper::getCipherOid($params),
            new OctetString(unpack("H*", $params->getIv())[1])
        );
    }

    /**
     * @param AesParams $params
     * @return Sequence
     */
    public function serialize(AesParams $params)
    {
        return $this->getAsn($params);
    }
}
