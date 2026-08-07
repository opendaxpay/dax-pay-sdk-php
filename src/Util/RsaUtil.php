<?php
declare(strict_types=1);

namespace DaxPay\OpenSdk\Util;

/**
 * RSA 签名工具 — 对照后端 RsaSignUtil
 * 使用 PHP 内置 ext-openssl（openssl_sign / openssl_verify），算法 SHA256withRSA
 */
class RsaUtil
{
    /**
     * 私钥签名（SHA256withRSA，UTF-8 字节，Base64 输出）
     */
    public static function sign(string $data, string $privateKeyPem): string
    {
        $signature = '';
        if (!openssl_sign($data, $signature, $privateKeyPem, \OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('RSA 签名失败: ' . \openssl_error_string());
        }
        return base64_encode($signature);
    }

    /**
     * 公钥验签
     */
    public static function verify(string $data, string $signB64, string $publicKeyPem): bool
    {
        $result = openssl_verify($data, base64_decode($signB64), $publicKeyPem, \OPENSSL_ALGO_SHA256);
        return $result === 1;
    }
}
