<?php

namespace Afk11\Pkcs5\Digest\Pbkdf2;

class Pbkdf2Factory
{
    const NAME_PBKDF2 = 'pkcs5PBKDF2';

    const HMAC_WITH_SHA1 = 'hmacWithSHA1';
    const PBKDF2_WITH_SHA224 = 'hmacWithSHA224';
    const PBKDF2_WITH_SHA256 = 'hmacWithSHA256';
    const PBKDF2_WITH_SHA384 = 'hmacWithSHA384';
    const PBKDF2_WITH_SHA512 = 'hmacWithSHA512';

    /**
     * @param string $method
     * @param int $iterationCount
     * @param int $keyLength
     * @param int $saltLen
     * @return Pbkdf2Params
     */
    public function pbkdf2($method = self::HMAC_WITH_SHA1, $iterationCount = 2048, $keyLength = null, $saltLen = 8)
    {
        if (!in_array($method, Pbkdf2AlgoOidMapper::getNames())) {
            throw new \RuntimeException('Pbkdf2 method not supported');
        }

        if (!is_numeric($keyLength)) {
            $keyLength = Pbkdf2AlgoOidMapper::getAlgoSizeByName($method);
        }

        if (!is_numeric($saltLen)) {
            throw new \RuntimeException('Salt length must be numeric');
        }

        $salt = random_bytes($saltLen);
        return new Pbkdf2Params($method, $salt, $iterationCount, $keyLength);
    }

    /**
     * @param int $iterationCount
     * @param int $keyLength
     * @param int $saltLen
     * @return Pbkdf2Params
     */
    public function pbkdf2_sha1($iterationCount = 2048, $keyLength = null, $saltLen = 8)
    {
        return $this->pbkdf2(self::HMAC_WITH_SHA1, $iterationCount, $keyLength, $saltLen);
    }

    /**
     * @param int $iterationCount
     * @param int $keyLength
     * @param int $saltLen
     * @return Pbkdf2Params
     */
    public function pbkdf2_sha224($iterationCount = 2048, $keyLength = null, $saltLen = 8)
    {
        return $this->pbkdf2(self::PBKDF2_WITH_SHA224, $iterationCount, $keyLength, $saltLen);
    }

    /**
     * @param int $iterationCount
     * @param int $keyLength
     * @param int $saltLen
     * @return Pbkdf2Params
     */
    public function pbkdf2_sha256($iterationCount = 2048, $keyLength = null, $saltLen = 8)
    {
        return $this->pbkdf2(self::PBKDF2_WITH_SHA256, $iterationCount, $keyLength, $saltLen);
    }

    /**
     * @param int $iterationCount
     * @param int $keyLength
     * @param int $saltLen
     * @return Pbkdf2Params
     */
    public function pbkdf2_sha384($iterationCount = 2048, $keyLength = null, $saltLen = 8)
    {
        return $this->pbkdf2(self::PBKDF2_WITH_SHA384, $iterationCount, $keyLength, $saltLen);
    }

    /**
     * @param int $iterationCount
     * @param int $keyLength
     * @param int $saltLen
     * @return Pbkdf2Params
     */
    public function pbkdf2_sha512($iterationCount = 2048, $keyLength = null, $saltLen = 8)
    {
        return $this->pbkdf2(self::PBKDF2_WITH_SHA512, $iterationCount, $keyLength, $saltLen);
    }
}
