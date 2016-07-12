<?php

namespace Afk11\Pkcs5\Digest\Pbkdf2;

class Pbkdf2Factory
{
    const NAME_PBKDF2 = 'pcks5PBKDF2';

    const PBKDF2_WITH_SHA224 = 'hmacWithSHA224';
    const PBKDF2_WITH_SHA256 = 'hmacWithSHA256';
    const PBKDF2_WITH_SHA384 = 'hmacWithSHA384';
    const PBKDF2_WITH_SHA512 = 'hmacWithSHA512';
    
    /**
     * @param string $method
     * @param int $iterationCount
     * @param int $keyLength
     * @return Pbkdf2Params
     */
    public function pbkdf2($method = 'sha1', $iterationCount = 2048, $keyLength = null)
    {
        $salt = random_bytes(8);
        return new Pbkdf2Params($method, $salt, $iterationCount, $keyLength);
    }
}
