<?php

namespace Afk11\Pkcs5\Tests\Digest\Pbkdf2;


use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Digest;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Factory;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Params;
use Afk11\Pkcs5\Tests\AbstractTestCase;

class Pbkdf2DigestTest extends AbstractTestCase
{
    public function getDigestVectors()
    {
        $digest = new Pbkdf2Digest();
        $hashSubjectData = 'data';
        return [
            // Test different key lengths
            [$digest, $hashSubjectData, Pbkdf2Factory::HMAC_WITH_SHA1, 'abcdabcd', 10000, 32, 'ec73c48bf78a51d2a26cb83417cbc37bce0f63500eebbf27cb2be51e9149703a'],
            [$digest, $hashSubjectData, Pbkdf2Factory::HMAC_WITH_SHA1, 'abcdabcd', 10000, 16, 'ec73c48bf78a51d2a26cb83417cbc37b'],

            // Notice how null keyLength will default to size of hash function
            [$digest, $hashSubjectData, Pbkdf2Factory::HMAC_WITH_SHA1, 'abcdabcd', 10000, null, 'ec73c48bf78a51d2a26cb83417cbc37bce0f6350'],
            [$digest, $hashSubjectData, Pbkdf2Factory::HMAC_WITH_SHA1, 'abcdabcd', 10000, 20, 'ec73c48bf78a51d2a26cb83417cbc37bce0f6350'],

            // Test another algorithm
            [$digest, $hashSubjectData, Pbkdf2Factory::PBKDF2_WITH_SHA256, 'abcdabcd', 10000, 32, '3dedce6ece876d6d176030714753991c948a89185d69bd0ddc5aa9fe121813b4'],
            [$digest, $hashSubjectData, Pbkdf2Factory::PBKDF2_WITH_SHA256, 'abcdabcd', 10000, null, '3dedce6ece876d6d176030714753991c948a89185d69bd0ddc5aa9fe121813b4']
        ];
    }

    /**
     * @param Pbkdf2Digest $pbkdf2
     * @param string $hashSubjectData
     * @param string $method
     * @param string $salt
     * @param int $iter
     * @param int $keyLen
     * @param string $expectedHash - in hex
     * @dataProvider getDigestVectors
     */
    public function testDigest(Pbkdf2Digest $pbkdf2, $hashSubjectData, $method, $salt, $iter, $keyLen, $expectedHash)
    {
        $params = new Pbkdf2Params($method, $salt, $iter, $keyLen);
        $data = $pbkdf2->hash($hashSubjectData, $params);
        $this->assertEquals(pack("H*", $expectedHash), $data);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Unknown algorithm
     */
    public function testMockWithUnknownInteralHashAlgo()
    {
        $mock = $this->getMockBuilder(Pbkdf2Params::class)
            ->disableOriginalConstructor()
            ->setMethods(['getMethod','getKeyLength','getSalt','getIterationCount'])
            ->getMock();

        $mock->expects($this->any())
            ->method('getMethod')
            ->willReturn('unknown');

        $pbkdf2 = new Pbkdf2Digest();
        $pbkdf2->hash('test', $mock);
    }
}