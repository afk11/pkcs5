<?php

namespace Afk11\Pkcs5\Tests\Digest;


use Afk11\Pkcs5\Digest\Digester;
use Afk11\Pkcs5\Digest\DigestParamsInterface;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Factory;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class DigesterTest extends AbstractTestCase
{
    public function testDigester()
    {
        $pbkdf2Params = (new Pbkdf2Factory())->pbkdf2();
        
        $digester = new Digester();
        $digester->digest('data', $pbkdf2Params);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Unknown or unsupported digest algorithm
     */
    public function testUnknownParams()
    {
        $mock = $this->getMockBuilder(DigestParamsInterface::class)
            ->setMethods(['getMethod'])
            ->getMock();

        $digester = new Digester();
        $digester->digest('data', $mock);

    }
}