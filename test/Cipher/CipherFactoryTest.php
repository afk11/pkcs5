<?php

namespace Afk11\Pkcs5\Tests\Digest;


use Afk11\Pkcs5\Cipher\Aes\AesFactory;
use Afk11\Pkcs5\Cipher\Aes\AesParams;
use Afk11\Pkcs5\Cipher\CipherFactory;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class CipherFactoryTest extends AbstractTestCase
{
    public function testFactoryPbkdf2()
    {
        $factory = new CipherFactory();
        $this->assertInstanceOf(AesFactory::class, $factory->getAesFactory());
    }

    /**
     * @return array
     */
    public function getNamedCipherMethods()
    {
        return [
            ['aes-128-cbc', AesParams::class],
            ['aes-192-cbc', AesParams::class],
            ['aes-256-cbc', AesParams::class]
        ];
    }

    /**
     * @param string $cipher
     * @param string $expectedInstance
     * @dataProvider getNamedCipherMethods
     */
    public function testParamsByName($cipher, $expectedInstance)
    {
        $params = CipherFactory::generateParamsByName($cipher);
        $this->assertInstanceOf($expectedInstance, $params);
        $this->assertEquals($cipher, $params->getName());
    }

    /**
     * @expectedExceptionMessage Unknown or unsupported cipher
     * @expectedException \RuntimeException
     */
    public function testBadParamsName()
    {
        CipherFactory::generateParamsByName('unknown');
    }
}