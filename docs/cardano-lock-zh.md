# Cardano lock 验签


该方案中，使用CBOR作为witness的结构，而不是传统的molecule。
同时会提供一个example作为

* 使用CBOR作为witness传输，而不是现有的moleculec
* 有一个example用来展示完整的签名


CBOR结构体：
```
83      # 数组 长度3
    82      # 存储交易的基本信息
        82      # 存储一些必要信息
            58 20   # sighash_all
                xxxxxxx
            58 16   # Public key
        58 20   # public key
            xxxxxxx
    xx      # 用户自定义信息
        xxxxxx
    58 40   # 签名数据
        xxxxxxx
```
说明：
* 第二组数据为用户自定义数据，如果没有填```00```即可
* 签名时，使用前两组数据进行。
* 签名前需要校验LockHash