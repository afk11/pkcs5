<?php

namespace Afk11\Pkcs5\Tests\Cipher\Aes;


use Afk11\Pkcs5\Cipher\Aes\AesParams;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class AesParamsTest extends AbstractTestCase
{
    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Invalid key length for AES
     */
    public function testInvalidKeySize()
    {
        new AesParams(str_repeat('A', 16), 1);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Invalid IV length - should be 16 bytes for AES
     */
    public function testInvalidIVSize()
    {
        new AesParams(str_repeat('A', 15), 256);
    }

    public function testValidInstanceMethods()
    {
        $iv = random_bytes(16);
        $length = 128;
        $params = new AesParams($iv, $length);

        $expectedName = "aes-$length-cbc";
        $this->assertEquals($iv, $params->getIv());
        $this->assertEquals($length, $params->getKeyLength());
        $this->assertEquals($expectedName, $params->getName());

    }
}