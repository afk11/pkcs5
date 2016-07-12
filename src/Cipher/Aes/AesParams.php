<?php

namespace Afk11\Pkcs5\Cipher\Aes;

use Afk11\Pkcs5\Cipher\CipherParamsInterface;

class AesParams implements CipherParamsInterface
{
    /**
     * @var string
     */
    private $name;

    /**
     * @var string
     */
    private $iv;

    /**
     * @var int
     */
    private $keyLength;

    /**
     * AesParams constructor.
     * @param string $iv
     * @param int $keyLength
     */
    public function __construct($iv, $keyLength)
    {
        if (strlen($iv) !== 16) {
            throw new \RuntimeException('Invalid IV length - should be 16 bytes for AES');
        }

        if (!in_array($keyLength, [128, 192, 256])) {
            throw new \RuntimeException('Invalid key length for AES');
        }

        $this->name = "aes-$keyLength-cbc";
        $this->iv = $iv;
        $this->keyLength = $keyLength;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @return string
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * @return int
     */
    public function getKeyLength()
    {
        return $this->keyLength;
    }
}
