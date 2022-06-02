## 简介

基于SM2椭圆曲线的ECDH 和 SHA256 安全哈希算法，构建的简单的PSI协议。

-  CPP  version 
   - [x] basic SM2 DDH PSI protocol
   - [ ] communication API Between Server and Client
   - [ ] some advance PSI protocol
-  Rust version
   - [ ] basic protocol
   - [ ] commuication    

## 使用说明

```shell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release	# Release mode
cmake .. -DCMAKE_BUILD_TYPE=Debug	# Debug mode
make
```


