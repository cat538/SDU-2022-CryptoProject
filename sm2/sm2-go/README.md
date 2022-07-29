# SM2 ( RFC6979 )

## Basic Imformation

- The implement of ``P256`` and ``sm3`` rely on <github.com/tjfoc/gmsm>
- [RFC6979](http://tools.ietf.org/html/rfc6979)
- SM2 standard:
  - [GB/T 32918.1-2016](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=3EE2FD47B962578070541ED468497C5B "SM2椭圆曲线公钥密码算法 第1部分 总则")
  - [GB/T 32918.2-2016](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=6F1FAEB62F9668F25F38E0BF0291D4AC "SM2椭圆曲线公钥密码算法 第2部分 数字签名算法")
  - [GB/T 32918.5-2017](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=728DEA8B8BB32ACFB6EF4BF449BC3077 "信息安全技术 SM2椭圆曲线公钥密码算法 第5部分：参数定义")
  - [GB/T 35276-2017](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=2127A9F19CB5D7F20D17D334ECA63EE5 "SM2密码算法使用规范")

## Use

```go
go test sm2
```

## Implementation

This section descript the implementation of RFC6979. Following chapter numbers refer to the chapter of RFC6979 standard.

RFC6976: Introduction **deterministic DSA and ECDSA**, which random number is generated deterministic function using private key.

- **2.1.  Key Parameters ``(E,q,G)``** : Provided by [GB/T 32918.5-2017](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=728DEA8B8BB32ACFB6EF4BF449BC3077 "信息安全技术 SM2椭圆曲线公钥密码算法 第5部分：参数定义") and implemented in [P256.go](https://github.com/tjfoc/gmsm/blob/master/sm2/p256.go).

- **2.3.  Integer Conversions**: The detailed explanation is commented in the given funcs.
  - 2.3.2.  Bit String to Integer ``conversion.go => func bits2int(b []byte, qlen int) *big.Int``
  - 2.3.3.  Integer to Octet String ``conversion.go => func bits2int(b []byte, qlen int) *big.Int``
  - 2.3.4.  Bit String to Octet String  ``conversion.go => func int2octets(x *big.Int, qlen int) []byte``  

- **3.2.  Generation of k** :``conversion.go => func RandWithPrivkey(priv *sm2.PrivateKey, digest []byte) (k*big.Int)``

## Result

![1](./figure/sm2.png)