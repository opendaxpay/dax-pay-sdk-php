<?php
declare(strict_types=1);

namespace DaxPay\OpenSdk\Tests;

use PHPUnit\Framework\TestCase;
use DaxPay\OpenSdk\Util\SignUtil;
use DaxPay\OpenSdk\Util\RsaUtil;

/**
 * 黄金向量测试 — 四语言 SDK 签名行为一致性硬验收
 * 对照 _doc/design/sdk-test-vectors.md
 */
class GoldenVectorTest extends TestCase
{
    private function privateKey(): string
    {
        return <<<'PEM'
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQClTNVpzrAL9IgQ
Z6HeV8Ov05gV9DLvgEVOxmxneCyaMLeAZBMyxs8Uvudw4QhPHercHLhg0Slhnoif
XI7tKO+/nm2gxcatfQzzYy9AN7A2BWcJZB8Yu4bWayzK3X9lRt9kXMTyiLwvk4o7
9x/STFcyraIFWepyBEg272z34gGk8PH8YTjkM8TJ2nwYuR0Xvs/HdEm1TzCugywZ
N2cgr/6OLfg3+marx5pRvizBWOAnabSEylCgWAld9TC4HRuItMGp4zX50d4QLuTY
RvZhdkOoRh3HKNurO3GbRKZjCXzzmZwY8E09O30CmhFZHcIZF8TylxCJ64HRh2x1
KH35lJojAgMBAAECggEAOR28XCwLzoW3Ahwc5UvkFPwDAAr6EqF60UZkrLfsiXat
4VIzBAeIBD4WkH1hNp06ysWtu95p8w4pXQ9JX48WkFp4vOW5ybZ85BhwejsDyxbA
zJDo4c3iQHKV7p7sZx0/EVmwv7EZfUL4r9GrECpKsvsmEb1I8g6iuUCvoVNZiBkf
BMy7bkDXJDJ/KYuRqEkfPfgqOOicJlXgjyiwtV9RN9SKErvnHo3kyt8RrSbCEYh2
y787gtPYf2U1XH674SAxd2Ki0rQ3CqHRjBUQGix7l8G5Hcv+TBJITNIktj8aJfu3
CvMnslQU9HEjbU8dMclywRSrjW839rym5lf+ptU/aQKBgQDJ6Bt5gsJlysy8P7ag
JlmQS0D5GmTx3GELLim1Uhbwwt6gCsQJf2l+0CnuEOBfJPGRdAUi35Tv8gDTG+9X
ai0wunNki6AHIfCtvY+zDxdgFtut1eIyq1ASFbAkW1jQRlXshVILAcU5GNjv8wOp
V9KcgkMGIsqGUdGb5drsbKDUPwKBgQDRlgtjktHXxDFsdkxUXCObCu6LevgdqgMH
qZ4mfui/NkTAuLFaFPddR+cmJNPPsy6MrHj97rZsPSTpaP0vQfJykFDlkm0xfBwv
dp41jLhWDN+OxsSs0eyoXptl3XUArsfipQ84tUODp9h86DoPs2oS39LuZj0DncY7
yXq1jCOxHQKBgFj603DfcXCOyV+E7KTzgbEXmRCu0yHLr3DP7U2dWcLM/nOlivNs
lT9v2aqzAU6s51Dkwoa15dtA2aAvxXDOuA+re8MpzWKXUIwg6D1PP0v3huS7R65w
1R7DNBcxsphHBwLvVlLHevVIwAIvJMPykjyrI4KGvp4nXKrJx4s97DrdAoGBAJab
401HuWH7C6UskYdhuvh0b51t3ZS7knfULODu++REZD21u0THoka3H+UqO8eatI3E
dyHLg+3eNoNAvghStJ4dFPUUN0GDNWHqNKC4odK8Z35bWgPyysTnT3ZxIN4/u0Yk
ZP7US1L1r716yBZ2UHiFvTcx4xCRNV3LWFHUBeYFAoGBAJKdUemy9ZFhtox7vLOG
U9EPScsh7xcyDcR8dEk+Ixjh8T8TnYjFxg4URAk7/uTki8WF9xcp6YntA92W22+J
Eje42gDW9bDb8I7BDlMigVCkM2A8cAsr3sHDdfo4N/PISL0dHpt2izEKWb6HZriK
AxnJl5/NyDmL/YfSVksVOZud
-----END PRIVATE KEY-----
PEM;
    }

    private function publicKey(): string
    {
        return <<<'PEM'
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApUzVac6wC/SIEGeh3lfD
r9OYFfQy74BFTsZsZ3gsmjC3gGQTMsbPFL7ncOEITx3q3By4YNEpYZ6In1yO7Sjv
v55toMXGrX0M82MvQDewNgVnCWQfGLuG1mssyt1/ZUbfZFzE8oi8L5OKO/cf0kxX
Mq2iBVnqcgRINu9s9+IBpPDx/GE45DPEydp8GLkdF77Px3RJtU8wroMsGTdnIK/+
ji34N/pmq8eaUb4swVjgJ2m0hMpQoFgJXfUwuB0biLTBqeM1+dHeEC7k2Eb2YXZD
qEYdxyjbqztxm0SmYwl885mcGPBNPTt9ApoRWR3CGRfE8pcQieuB0YdsdSh9+ZSa
IwIDAQAB
-----END PUBLIC KEY-----
PEM;
    }

    public function testV1Basic(): void
    {
        $json = '{"mchNo":"M200000001","appId":"APP001","reqId":"REQ20250805143000001",' .
            '"reqTime":"2025-08-05 14:30:00","nonceStr":"5K8264ILTKCH16CQ2502SI8ZNMTM67VS",' .
            '"bizOrderNo":"PAY20250805143000001","title":"测试商品","amount":100,' .
            '"method":"wechat_qr","notifyUrl":"https://example.com/notify"}';
        $expectedSignStr = 'amount=100&appId=APP001&bizOrderNo=PAY20250805143000001&mchNo=M200000001' .
            '&method=wechat_qr&nonceStr=5K8264ILTKCH16CQ2502SI8ZNMTM67VS' .
            '&notifyUrl=https://example.com/notify&reqId=REQ20250805143000001' .
            '&reqTime=2025-08-05 14:30:00&title=测试商品';
        $expectedSign = 'nleBG/KSrl5UE4o6XKMYmZ/Oz+BgUeyHorB1TXYG9w5WJ4y0DxuUTubjXbwdW1pZ' .
            'KNwV022EdasVP5V1kQUStmYfDcHxbSaTM3c3/IYXNGM2xVlvh1geJA1JzNgL2ErUHhAZUhZYBk6RnjhzV' .
            'XQl3JRSipKyjx5jPfAcNrI7K5RbBlDvOzbLJw2Sce+lXZFGkgAmGD1LjoX5rFMk7pf7m9PF+Njm69bTI' .
            '3J45TLWlv1iTRHH4BZG6BOiKleoH3TfOn73QubxQ4/2HIwognTmKawGSR3vjiM7rvSCDosyC5d5ZVltR' .
            'eZiHA6/AsdmXcT/EKc7VhCzjP3YgHxBPyZElQ==';

        $signStr = SignUtil::buildSignStr($json);
        self::assertSame($expectedSignStr, $signStr);
        $sign = RsaUtil::sign($signStr, $this->privateKey());
        self::assertSame($expectedSign, $sign);
        self::assertTrue(RsaUtil::verify($signStr, $sign, $this->publicKey()));
    }

    public function testV2Nested(): void
    {
        $json = '{"mchNo":"M200000001","appId":"APP001","reqId":"REQ20250805143000002",' .
            '"reqTime":"2025-08-05 14:30:00","bizOrderNo":"PAY20250805143000002",' .
            '"title":"测试商品 & 附录","amount":8888,"method":"alipay_qr",' .
            '"attach":"{\"order\":\"order_0000001\"}",' .
            '"terminal":{"terminalNo":"T001","storeNo":"S001","operatorId":"OP01"},' .
            '"goodsDetail":[{"goodsId":"G001","goodsName":"商品A","quantity":1,"unitPrice":5000},' .
            '{"goodsId":"G002","goodsName":"商品B","quantity":2,"unitPrice":1944}]}';
        $expectedSignStr = 'amount=8888&appId=APP001&attach={"order":"order_0000001"}' .
            '&bizOrderNo=PAY20250805143000002&goodsDetail[0].goodsId=G001' .
            '&goodsDetail[0].goodsName=商品A&goodsDetail[0].quantity=1&goodsDetail[0].unitPrice=5000' .
            '&goodsDetail[1].goodsId=G002&goodsDetail[1].goodsName=商品B' .
            '&goodsDetail[1].quantity=2&goodsDetail[1].unitPrice=1944&mchNo=M200000001' .
            '&method=alipay_qr&reqId=REQ20250805143000002&reqTime=2025-08-05 14:30:00' .
            '&terminal.operatorId=OP01&terminal.storeNo=S001&terminal.terminalNo=T001' .
            '&title=测试商品 & 附录';
        $expectedSign = 'LyKKVoDfVtHHBrrFHg4faEVkqh53uNy1FaC/wXmA3QqCosFc2Ed7AK6F7D7i7Ulic' .
            '0fSzFmi2vw/Bzt0y+sba/UMVuKdUEum+nG6psCjGjwTVAwShoVAznxzKfhE5vxZaA0wxvaN2HHpjrTEq' .
            'JiyVjbrK6tkjjKcA67QyeJS+lu46p7MIhPjMMnExgxWPgkwtlee5XuHoKYlgDk4oReAf5srcxfLI5f44' .
            'KwJrhHJFEY7w1iYtpMqkF6Ont0Zp9+MNAfhyZqy5eLPk76TuLzBSPdBMb8cSlM/5qjuBlFnECaW8yj8e' .
            'FOyly9CN8071HjrHmxv002BqEA1BXZ9Sqdh5g==';

        $signStr = SignUtil::buildSignStr($json);
        self::assertSame($expectedSignStr, $signStr);
        $sign = RsaUtil::sign($signStr, $this->privateKey());
        self::assertSame($expectedSign, $sign);
        self::assertTrue(RsaUtil::verify($signStr, $sign, $this->publicKey()));
    }

    public function testV3Verify(): void
    {
        // resTime 使用北京时间（平台对外契约）
        $json = '{"code":0,"msg":"success","data":{"bizOrderNo":"PAY20250805143000001",' .
            '"orderNo":"DEV_P20250805143000001","tradeNo":"T202508051430","status":"success",' .
            '"amount":100,"payBody":"https://example.com/pay?token=abc123"},' .
            '"reqId":"REQ20250805143000001","resTime":"2025-08-05 14:30:00"}';
        $expectedSignStr = 'code=0&data.amount=100&data.bizOrderNo=PAY20250805143000001' .
            '&data.orderNo=DEV_P20250805143000001&data.payBody=https://example.com/pay?token=abc123' .
            '&data.status=success&data.tradeNo=T202508051430&msg=success' .
            '&reqId=REQ20250805143000001&resTime=2025-08-05 14:30:00';
        $expectedSign = 'juvn6a3t8AHlD6XJHUFdaMXPFb/BfMCCnfUC8/oledpfitYRvWmZBrjrQlwmuqybhaeeyk' .
            'O3ds5AZT4fqE59duVjAeV9YxoVhsnJ+Sk/x6hAYnd70z+zWHP0AzKIip1EfGwx5/GsiOfz' .
            'yuh3u0RlP1lBAdPMqdXf12I69mZjyNGWv2WplggV95PRX6bqlXVTPwfgTnJHSobKL4z0rN' .
            'D0nTg/+qBqh8Px8aeNwLDh6mrpuLL6PKWVf9pmMzHhJzoj/CYJ2Ith8ciFdyVVB9vadAbk' .
            'xg6JUjgaZ41S5+W2tQrrdw/oJ7GFcYHuDwmeKKVeZKu+nMrA5TtY5PQj+CrK3Q==';

        $signStr = SignUtil::buildSignStr($json);
        self::assertSame($expectedSignStr, $signStr);
        $sign = RsaUtil::sign($signStr, $this->privateKey());
        self::assertSame($expectedSign, $sign);
        self::assertTrue(RsaUtil::verify($signStr, $sign, $this->publicKey()));
    }

    /**
     * PEM 解析校验（联调 demo 保存配置时用）：
     * 合法 PEM 通过、格式非法/内容损坏/空串一律不通过（避免无效密钥进入配置后才在交易时暴露）
     */
    public function testPemValidation(): void
    {
        self::assertTrue(RsaUtil::isValidPrivateKey($this->privateKey()));
        self::assertTrue(RsaUtil::isValidPublicKey($this->publicKey()));

        // 空串与随机文本
        self::assertFalse(RsaUtil::isValidPrivateKey(''));
        self::assertFalse(RsaUtil::isValidPublicKey(''));
        self::assertFalse(RsaUtil::isValidPrivateKey('not-a-pem'));
        self::assertFalse(RsaUtil::isValidPublicKey('not-a-pem'));

        // 头尾正确但 base64 体损坏
        $broken = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
        self::assertFalse(RsaUtil::isValidPrivateKey($broken));

        // 公私钥两者必须严格区分，不能互相通过
        self::assertFalse(RsaUtil::isValidPrivateKey($this->publicKey()));
        self::assertFalse(RsaUtil::isValidPublicKey($this->privateKey()));
    }
}
