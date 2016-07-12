<?php

namespace Afk11\Pkcs5\Serializer\Digest\Params;

use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2AlgoOidMapper;
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
        $sequence = new Sequence(
            new OctetString($params->getSalt()),
            new Integer($params->getIterationCount())
        );

        if ($params->getKeyLength() !== null) {
            $sequence[] = new Integer($params->getKeyLength());
        }

        if ($params->getMethod() !== null) {
            $sequence[] = new AlgorithmIdentifier(Pbkdf2AlgoOidMapper::getOidByName($params->getMethod()));
        }
        
        return $sequence->getBinary();
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
