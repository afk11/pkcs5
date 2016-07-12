<?php

namespace Afk11\Pkcs5\Tests\Digest\Pbkdf2;


use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Factory;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class Pbkdf2FactoryTest extends AbstractTestCase
{
    public function testFactoryDefaults()
    {
        $factory = new Pbkdf2Factory();
        $params = $factory->pbkdf2();
        $this->assertEquals(null, $params->getKeyLength());
        $this->assertEquals(2048, $params->getIterationCount());
        $this->assertEquals('sha1', $params->getMethod());
        $this->assertInternalType('string', $params->getSalt());
        $this->assertEquals(8, strlen($params->getSalt()));
    }

    public function testFactoryParams()
    {
        $factory = new Pbkdf2Factory();
        $algo = 'sha256';
        $i = 100000;
        $keylen = 32;
        $params = $factory->pbkdf2($algo, $i, $keylen);
        $this->assertEquals($keylen, $params->getKeyLength());
        $this->assertEquals($i, $params->getIterationCount());
        $this->assertEquals($algo, $params->getMethod());
        $this->assertInternalType('string', $params->getSalt());
    }
}