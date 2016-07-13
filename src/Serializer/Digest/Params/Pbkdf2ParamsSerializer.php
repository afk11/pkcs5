<?php

namespace Afk11\Pkcs5\Serializer\Digest\Params;

use Afk11\Pkcs5\Digest\DigestFactory;
use Afk11\Pkcs5\Digest\DigestOidMapper;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2AlgoOidMapper;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Factory;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Params;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use FG\X509\AlgorithmIdentifier;

class Pbkdf2ParamsSerializer
{
    /**
     * @param Pbkdf2Params $params
     * @return Sequence
     */
    public function getAsn(Pbkdf2Params $params)
    {
        $inner = new Sequence(
            new OctetString(unpack("H*", $params->getSalt())[1]),
            new Integer($params->getIterationCount())
        );

        if ($params->getKeyLength() !== null) {
            $inner[] = new Integer($params->getKeyLength());
        }

        if ($params->getMethod() !== null) {
            $inner[] = new AlgorithmIdentifier(Pbkdf2AlgoOidMapper::getOidByName($params->getMethod())->getContent());
        }

        return new Sequence(
            DigestOidMapper::getOidByName(Pbkdf2Factory::NAME_PBKDF2),
            $inner
        );
    }

    /**
     * @param Pbkdf2Params $params
     * @return string
     */
    public function serialize(Pbkdf2Params $params)
    {
        return $this->getAsn($params)->getBinary();
    }
}
