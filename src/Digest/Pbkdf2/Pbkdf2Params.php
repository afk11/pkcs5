<?php

namespace Afk11\Pkcs5\Digest\Pbkdf2;

class Pbkdf2Params
{
    /**
     * @var string
     */
    private $salt;

    /**
     * @var int
     */
    private $iterationCount;

    /**
     * @var int
     */
    private $keyLength;

    /**
     * @var string
     */
    private $method;

    /**
     * Pbkdf2Params constructor.
     * @param string $method
     * @param string $salt
     * @param int $iterationCount
     * @param int $keyLength
     */
    public function __construct($method, $salt, $iterationCount, $keyLength = null)
    {
        if (!in_array($method, Pbkdf2AlgoOidMapper::getNames())) {
            throw new \RuntimeException('Pbkdf2 method not supported');
        }
        
        if (!is_numeric($iterationCount)) {
            throw new \RuntimeException('Iteration count must be numeric');
        }

        $this->salt = $salt;
        $this->iterationCount = $iterationCount;
        $this->keyLength = $keyLength;
        $this->method = $method;
    }

    /**
     * @return string
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * @return int
     */
    public function getIterationCount()
    {
        return $this->iterationCount;
    }

    /**
     * @return int
     */
    public function getKeyLength()
    {
        return $this->keyLength;
    }

    /**
     * @return string
     */
    public function getMethod()
    {
        return $this->method;
    }
}
