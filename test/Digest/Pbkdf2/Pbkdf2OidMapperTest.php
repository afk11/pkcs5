<?php

namespace Afk11\Pkcs5\Tests\Digest\Pbkdf2;


use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2AlgoOidMapper;
use Afk11\Pkcs5\Digest\Pbkdf2\Pbkdf2Factory;
use Afk11\Pkcs5\Tests\AbstractTestCase;
use FG\ASN1\Universal\ObjectIdentifier;

class Pbkdf2OidMapperTest extends AbstractTestCase
{
    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Unknown or unsupported pbkdf2 algorithm
     */
    public function testGetSizeUnknownMethod()
    {
        Pbkdf2AlgoOidMapper::getAlgoSizeByName('unknown');
    }

    public function testGetSize()
    {
        $this->assertInternalType('int', Pbkdf2AlgoOidMapper::getAlgoSizeByName(Pbkdf2Factory::PBKDF2_WITH_SHA224));
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testGetOidByNameInvalid()
    {
        Pbkdf2AlgoOidMapper::getOidByName('unknown');
    }

    public function testGetOidByName()
    {
        $this->assertInstanceOf(ObjectIdentifier::class, Pbkdf2AlgoOidMapper::getOidByName(Pbkdf2Factory::PBKDF2_WITH_SHA224));
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testGetNameByOidInvalid()
    {
        Pbkdf2AlgoOidMapper::getNameFromOid(new ObjectIdentifier('1.1'));
    }
    
    public function testGetNameFromOid()
    {
        $oid = Pbkdf2AlgoOidMapper::getOidByName(Pbkdf2Factory::PBKDF2_WITH_SHA224);
        $name = Pbkdf2AlgoOidMapper::getNameFromOid($oid);
        $this->assertEquals(Pbkdf2Factory::PBKDF2_WITH_SHA224, $name);
    }
}