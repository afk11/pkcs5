<?php

namespace Afk11\Pkcs5\Tests\Cipher\Aes;


use Afk11\Pkcs5\Cipher\Aes\AesFactory;
use Afk11\Pkcs5\Cipher\Aes\AesParams;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class AesFactoryTest extends AbstractTestCase
{
    public function getFactoryVectors()
    {
        $aesFactory = new AesFactory();
        return [
            [$aesFactory, 'aes128', 128],
            [$aesFactory, 'aes192', 192],
            [$aesFactory, 'aes256', 256],
        ];
    }

    /**
     * @dataProvider getFactoryVectors
     * @param AesFactory $factory
     * @param string $method
     * @param int $keyLength
     */
    public function testFactoryVectors(AesFactory $factory, $method, $keyLength)
    {
        /** @var AesParams $params */
        $params = $factory->{$method}();
        $this->assertInstanceOf(AesParams::class, $params);
        $this->assertEquals("aes-$keyLength-cbc", $params->getName());
        $this->assertEquals($keyLength, $params->getKeyLength());
    }
}