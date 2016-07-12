<?php

namespace Afk11\Pkcs5\Digest;

use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Factory;

class DigestFactory
{
    /**
     * @return Pbkdf2Factory
     */
    public static function getPbkdf2Factory()
    {
        return new Pbkdf2Factory();
    }
}
