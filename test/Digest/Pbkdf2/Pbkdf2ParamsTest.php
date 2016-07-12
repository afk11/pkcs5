<?php

namespace Afk11\Pkcs5\Tests\Digest\Pbkdf2;


use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Params;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class Pbkdf2ParamsTest extends AbstractTestCase
{
    public function testInstance()
    {
        $method = 'sha256';
        $salt = 'abcd01234';
        $iterCount = 1000;
        $keyLength = 32;
        $params = new Pbkdf2Params($method, $salt, $iterCount, $keyLength);

        $this->assertEquals($method, $params->getMethod());
        $this->assertEquals($salt, $params->getSalt());
        $this->assertEquals($iterCount, $params->getIterationCount());
        $this->assertEquals($keyLength, $params->getKeyLength());
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Iteration count must be numeric
     */
    public function testInvalidAlgo()
    {
        $method = 'sha256';
        $salt = 'abcd01234';
        $iterCount = 'blah';
        $keyLength = 32;
        new Pbkdf2Params($method, $salt, $iterCount, $keyLength);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Pbkdf2 method not supported
     */
    public function testInvalidKeyLength()
    {
        $method = 'invalid';
        $salt = 'abcd01234';
        $iterCount = 1000;
        $keyLength = 32;
        new Pbkdf2Params($method, $salt, $iterCount, $keyLength);
    }
}