<?php
declare(strict_types=1);

namespace DaxPay\OpenSdk;

use DaxPay\OpenSdk\Util\SignUtil;
use DaxPay\OpenSdk\Util\RsaUtil;

/**
 * DaxPay SDK 客户端 — 对照 sdk-contract.md 第十节
 * 走 JSON 签名路径（reqTime 已序列化为 GMT+8 字面量），与后端验签一致
 */
class Client
{
    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * 通用执行入口：自动填充公共参数 → JSON 签名 → POST → 验签 → 返回关联数组
     * @return array<string,mixed> DaxResult 关联数组
     */
    public function execute(string $path, array $param): array
    {
        // 注入公共字段
        $param['mchNo'] = $param['mchNo'] ?? $this->config->getMchNo();
        if ($this->config->getAppId() !== null) {
            $param['appId'] = $param['appId'] ?? $this->config->getAppId();
        }
        $param['reqId'] = $param['reqId'] ?? $this->generateReqId();
        $param['reqTime'] = $param['reqTime'] ?? $this->nowGmt8();
        $param['nonceStr'] = $param['nonceStr'] ?? $this->generateNonce();

        // 走 JSON 签名路径
        $jsonFlags = \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES;
        $jsonForSign = json_encode($param, $jsonFlags);
        $signStr = SignUtil::buildSignStr($jsonForSign);
        $param['sign'] = RsaUtil::sign($signStr, $this->config->getPrivateKey());
        $body = json_encode($param, $jsonFlags);

        // POST
        $url = $this->config->getServiceUrl() . $path;
        $rawBody = $this->httpPost($url, $body);

        // 验签（用原始 body 字符串）
        $result = json_decode($rawBody, true, 512, \JSON_BIGINT_AS_STRING);
        if (!is_array($result)) {
            throw new \RuntimeException('响应解析失败: ' . $rawBody);
        }
        if (isset($result['sign']) && $result['sign'] !== '') {
            if (!SignUtil::verify($rawBody, $result['sign'], $this->config->getPublicKey())) {
                throw new \RuntimeException('响应验签失败');
            }
        }
        if (($result['code'] ?? -1) !== 0) {
            throw new \RuntimeException('[' . ($result['code'] ?? -1) . '] ' . ($result['msg'] ?? ''));
        }
        return $result;
    }

    /**
     * 支付下单便捷方法 — POST /unipay/pay
     * @param array<string,mixed> $param 支付参数（bizOrderNo/title/amount/method/notifyUrl 等）
     * @return array<string,mixed> DaxResult 关联数组
     */
    public function pay(array $param): array
    {
        return $this->execute('/unipay/pay', $param);
    }

    /**
     * 回调验签（原始 HTTP body 字符串）— 对照契约第八节
     */
    public function verifyNotice(string $rawBody): bool
    {
        $obj = json_decode($rawBody, true, 512, \JSON_BIGINT_AS_STRING);
        if (!isset($obj['sign'])) {
            return false;
        }
        return SignUtil::verify($rawBody, $obj['sign'], $this->config->getPublicKey());
    }

    /**
     * HTTP POST（用 stream context，零 curl 依赖）
     */
    private function httpPost(string $url, string $body): string
    {
        $opts = [
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json; charset=utf-8\r\n",
                'content' => $body,
                'timeout' => $this->config->getTimeout() / 1000,
                'ignore_errors' => true,
            ],
        ];
        $context = stream_context_create($opts);
        $response = @file_get_contents($url, false, $context);
        $code = 200;
        if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
            $code = (int) $m[1];
        }
        if ($response === false && $code !== 200) {
            throw new \RuntimeException('请求失败: HTTP ' . $code);
        }
        if ($code !== 200) {
            throw new \RuntimeException('HTTP ' . $code . ': ' . $response);
        }
        return (string) $response;
    }

    /**
     * 当前时间的 GMT+8 字面量（yyyy-MM-dd HH:mm:ss）
     */
    private function nowGmt8(): string
    {
        return gmdate('Y-m-d H:i:s', time() + 8 * 3600);
    }

    private function generateReqId(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    private function generateNonce(): string
    {
        return bin2hex(random_bytes(16));
    }
}
