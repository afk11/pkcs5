<?php

namespace Afk11\Pkcs5\Tests\Digest;


use Afk11\Pkcs5\Cipher\Aes\AesFactory;
use Afk11\Pkcs5\Cipher\CipherParamsInterface;
use Afk11\Pkcs5\Cipher\Crypter;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class CrypterTest extends AbstractTestCase
{
    public function testCrypter()
    {
        $aesParams = (new AesFactory())->aes128();
        $key = str_repeat('A', 16);
        $privData = 'data';
        $crypter = new Crypter();
        $cipherText = $crypter->encrypt($privData, $key, $aesParams);
        $plainText = $crypter->decrypt($cipherText, $key, $aesParams);
        $this->assertEquals($privData, $plainText);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Unknown or unsupported cipher
     */
    public function testUnknownParams()
    {
        $mock = $this->getMockBuilder(CipherParamsInterface::class)
            ->setMethods(['getName'])
            ->getMock();

        $digester = new Crypter();
        $digester->encrypt('data', 'aaaaaaaaaaaaaaaa', $mock);

    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Unknown or unsupported cipher
     */
    public function testUnknownCipherDecrypt()
    {
        $mock = $this->getMockBuilder(CipherParamsInterface::class)
            ->setMethods(['getName'])
            ->getMock();

        $digester = new Crypter();
        $digester->decrypt('data', 'aaaaaaaaaaaaaaaa', $mock);

    }
}