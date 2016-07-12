<?php

namespace Afk11\Pkcs5\Tests\Digest;


use Afk11\Pkcs5\Cipher\Aes\AesFactory;
use Afk11\Pkcs5\Cipher\CipherFactory;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class CipherFactoryTest extends AbstractTestCase
{
    public function testFactoryPbkdf2()
    {
        $factory = new CipherFactory();
        $this->assertInstanceOf(AesFactory::class, $factory->getAesFactory());
    }
}