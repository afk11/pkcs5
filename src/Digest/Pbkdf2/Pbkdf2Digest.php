<?php

namespace Afk11\Pkcs5\Digest\Pbkdf2;

class Pbkdf2Digest
{
    /**
     * @param string $password
     * @param Pbkdf2Params $params
     * @return string
     */
    public function hash($password, Pbkdf2Params $params)
    {
        $keyLength = $params->getKeyLength();
        return hash_pbkdf2($params->getMethod(), $password, $params->getSalt(), $params->getIterationCount(), $keyLength, true);
    }
}
