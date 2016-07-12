<?php

namespace Afk11\Pkcs5\Tests\Digest\Pbkdf2;


use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Digest;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Factory;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Params;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class Pbkdf2FactoryTest extends AbstractTestCase
{
    public function testFactoryDefaults()
    {
        $factory = new Pbkdf2Factory();
        $params = $factory->pbkdf2();
        $this->assertEquals(null, $params->getKeyLength());
        $this->assertEquals(2048, $params->getIterationCount());
        $this->assertEquals(Pbkdf2Factory::HMAC_WITH_SHA1, $params->getMethod());
        $this->assertInternalType('string', $params->getSalt());
        $this->assertEquals(8, strlen($params->getSalt()));
    }

    public function testFactoryParams()
    {
        $factory = new Pbkdf2Factory();
        $algo = Pbkdf2Factory::PBKDF2_WITH_SHA256;
        $i = 100000;
        $keylen = 32;
        $params = $factory->pbkdf2($algo, $i, $keylen);
        $this->assertEquals($keylen, $params->getKeyLength());
        $this->assertEquals($i, $params->getIterationCount());
        $this->assertEquals($algo, $params->getMethod());
        $this->assertInternalType('string', $params->getSalt());
    }

    public function getFactoryVectors()
    {
        $pbkdf2 = new Pbkdf2Factory();
        return [
            [$pbkdf2, 'pbkdf2_sha1', Pbkdf2Factory::HMAC_WITH_SHA1],
            [$pbkdf2, 'pbkdf2_sha224', Pbkdf2Factory::PBKDF2_WITH_SHA224],
            [$pbkdf2, 'pbkdf2_sha256', Pbkdf2Factory::PBKDF2_WITH_SHA256],
            [$pbkdf2, 'pbkdf2_sha384', Pbkdf2Factory::PBKDF2_WITH_SHA384],
            [$pbkdf2, 'pbkdf2_sha512', Pbkdf2Factory::PBKDF2_WITH_SHA512],
        ];
    }

    /**
     * @param Pbkdf2Factory $pbkdf2
     * @param string $method
     * @param string $expectedAlgo
     * @dataProvider getFactoryVectors
     */
    public function testFactoryMethods(Pbkdf2Factory $pbkdf2, $method, $expectedAlgo)
    {
        /** @var Pbkdf2Params $params */
        $params = $pbkdf2->{$method}();
        $this->assertInstanceOf(Pbkdf2Params::class, $params);
        $this->assertEquals($expectedAlgo, $params->getMethod());
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Salt length must be numeric
     */
    public function testInvalidSaltLen()
    {
        $factory = new Pbkdf2Factory();
        $factory->pbkdf2(Pbkdf2Factory::PBKDF2_WITH_SHA224, 100, null, 'string');
    }
}