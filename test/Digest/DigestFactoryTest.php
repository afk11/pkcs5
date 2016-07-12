<?php

namespace Afk11\Pkcs5\Tests\Digest;


use Afk11\Pkcs5\Digest\DigestFactory;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Factory;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class DigestFactoryTest extends AbstractTestCase
{
    public function testFactoryPbkdf2()
    {
        $factory = new DigestFactory();
        $this->assertInstanceOf(Pbkdf2Factory::class, $factory->getPbkdf2Factory());
    }
}