# DaxPay Open SDK for PHP

DaxPay 开放支付平台 PHP SDK，封装支付下单、关闭、退款、订单查询与回调验签。

> **适配 DaxPay Open ≥ 1.0** · **PHP 7.4+** · LGPL-3.0 · 零第三方依赖（ext-openssl / ext-json）

## 功能

- RSA 双向签名（SHA256withRSA，`openssl_sign`），自动签名请求 / 验签响应与回调
- 走 JSON 签名路径，与开源版后端 `reqTime` 契约对齐
- 核心支付接口：pay / close / refund / query pay-order / query refund-order
- 异步回调验签

## 安装（源码引入）

`composer.json`：

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/daxpay/daxpay-open-sdk-php.git" }
    ],
    "require": {
        "daxpay/open-sdk": "dev-main"
    }
}
```

```bash
composer install
```

```php
use DaxPay\OpenSdk\Client;
use DaxPay\OpenSdk\Config;
```

## 快速开始

```php
$config = (new Config())
    ->setServiceUrl('https://sandbox.daxpay.cn')
    ->setMchNo('M200000001')
    ->setAppId('APP001')
    ->setPrivateKey($merchantPrivateKeyPem)     // PEM 文本
    ->setPublicKey($platformPublicKeyPem);       // PEM 文本
$client = new Client($config);

// 支付下单
$result = $client->pay([
    'bizOrderNo' => 'PAY20250805001',
    'title'      => '测试商品',
    'amount'     => 100,            // 分
    'method'     => 'wechat_qr',
    'notifyUrl'  => 'https://example.com/notify',
]);

// 回调验签
// $ok = $client->verifyNotice($rawBody);
```

> 完整可运行示例见 `examples/`（实现中）。

## 契约文档

- 接口契约：[`daxpay-open/_doc/design/sdk-contract.md`](../../dax-pay-open/_doc/design/sdk-contract.md)
- 黄金测试向量：[`sdk-test-vectors.md`](../../dax-pay-open/_doc/design/sdk-test-vectors.md)

## License

LGPL-3.0，与主仓库 [DaxPay Open](../../dax-pay-open) 同协议。
