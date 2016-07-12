<?php

namespace Afk11\Pkcs5\Cipher\Aes;

class AesCrypt
{
    /**
     * @param string $key
     * @param AesParams $params
     */
    private function checkKeyLength($key, AesParams $params)
    {
        if (strlen($key) !== $params->getKeyLength() / 8) {
            throw new \RuntimeException('Key does not match specified keyLength');
        }
    }

    /**
     * @param string $data
     * @param string $key
     * @param AesParams $params
     * @return string
     */
    public function encrypt($data, $key, AesParams $params)
    {
        $this->checkKeyLength($key, $params);

        return openssl_encrypt($data, $params->getName(), $key, 0, $params->getIv());
    }

    /**
     * @param string $data
     * @param string $key
     * @param AesParams $params
     * @return string
     */
    public function decrypt($data, $key, AesParams $params)
    {
        $this->checkKeyLength($key, $params);

        return openssl_decrypt($data, $params->getName(), $key, 0, $params->getIv());
    }
}
