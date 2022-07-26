# Project about Zero Knowledge Proof

Try to build zkp app to proof CET6 Score > 425

- [x] Basic impl based on miden VM
- [x] Basic impl based on libsnark

## 项目说明

使用zkVM和libsnark实现了对于六级成绩是否大于425的零知识证明电路。

## [MidenVM](https://github.com/maticnetwork/miden)
### 使用方法
Miden VM 是Rust零知识虚拟机，使用Miden 可以快速高效的构造零知识证明应用。
```shell
cargo build # Debug mod
cargo build --release # Release mod
cd target
cd debug # cd release
./Poc_of_zkp.exe 
```
### 运行截图
程序运行如下图所示
![1](/poc-of-zkp/figure/example_1.jpg)

## [libsnark](https://github.com/scipr-lab/libsnark)
libsnark 提供了常见的ZKP协议的c++ 实现，实力libsnark 中的gadget可以实现比较电路
### 使用方法
``` shell
cd libsnark-version
git submodule init && git submodule update
mkdir build && cd build && cmake ..
make
cd src
./cet6
```
### 运行截图
![2](/poc-of-zkp/figure/example_2.jpg)

### 贡献
刘齐：ZKP项目
