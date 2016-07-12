<?php

namespace Afk11\Pkcs5\Digest;

use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Digest;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Params;

class Digester
{
    /**
     * @var Pbkdf2Digest
     */
    private $pbkdf2;
    
    public function __construct()
    {
        $this->pbkdf2 = new Pbkdf2Digest();
    }

    /**
     * @param string $data
     * @param DigestParamsInterface $digestParams
     * @return string
     */
    public function digest($data, DigestParamsInterface $digestParams)
    {
        if ($digestParams instanceof Pbkdf2Params) {
            return $this->pbkdf2->hash($data, $digestParams);
        }

        throw new \RuntimeException('Unknown or unsupported digest algorithm');
    }
}
