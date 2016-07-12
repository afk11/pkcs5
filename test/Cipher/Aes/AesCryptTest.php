<?php

namespace Afk11\Pkcs5\Tests\Cipher\Aes;


use Afk11\Pkcs5\Cipher\Aes\AesCrypt;
use Afk11\Pkcs5\Cipher\Aes\AesFactory;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class AesCryptTest extends AbstractTestCase
{
    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Key does not match specified keyLength
     */
    public function testRejectsInvalidKeySize()
    {
        $privKey = str_repeat('A', 16);
        $params = (new AesFactory())->aes256();

        (new AesCrypt())->encrypt('This is a secret message', $privKey, $params);
    }

    public function testConsistency()
    {
        $data = 'This is a secret message';

        $factory = new AesFactory();
        $params = $factory->aes256();

        $crypter = new AesCrypt();
        $privKey = str_repeat('A', 32);
        $cipherText = $crypter->encrypt($data, $privKey, $params);
        $plainText = $crypter->decrypt($cipherText, $privKey, $params);
        $this->assertEquals($data, $plainText);
    }
}