## 项目说明

Rust Crypto是一个致力于使用pure rust 编写密码库的工程

在本项目中使用了**RustCrypto** 中实现的SM3作为子程序调用

```bash
cargo b --release
cargo r
```

## 测试结果

测试环境：

- CPU: i5-1035G1
- RAM: 16GB

8线程完成48比特碰撞寻找在**400ms**左右，完成50比特碰撞寻找在**40s**左右

- 运行截图: [上一级目录README](../README.md)
