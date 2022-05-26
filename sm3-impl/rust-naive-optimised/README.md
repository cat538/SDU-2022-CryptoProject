## 项目说明

- `sm3_basic`是按照2010年12月国家密码管理局颁布的《SM3密码杂凑算法》进行的基本实现，没有任做何优化

  ```rust
  fn sm3_base(m: &Vec<u8>) -> [u8;32]
  ```

- `sm3_opt`在上一步实现的基础上增加了条件分支消除，尽可能地消除了非必需的内存分配，使用T状态预计算查表优化；初版优化考虑SIMD，但后续测试中发现显式使用SIMD效果并不好，猜想考虑`chunks_exact`等存在数据并行操作的函数会被编译器使用SIMD自动优化；也可能因为瓶颈不在load，而是在压缩函数那里（显然），但具体的原因和改进还需进一步profiling

  ```rust
  struct Sm3Dm
  impl Sm3Dm{
      fn new() -> Self
      fn update(&mut self, m: impl AsRef<u8>)
      fn finalize(&mut self) -> [u8;32]
  }
  ```

运行test和benchmark：

```bash
cargo test
cargo bench
```

bench后打开`target/criterion/report/index.html`有详细对比分析报告图

## 项目依赖

- base(naive)和opt版本的`sm3`实现均不依赖第三方库，self-contained；
- 作为对比测试，引入**RustCrypto**项目中的`sha2`, `sh3`, `sm3`模块与我的实现进行对比
- 单元测试依赖`rand`；基准测试依赖`criterion`；

## 测试结果

|                    | sha256    | keccak256 | sm3_lib | sm3_opt | sm3_base |
| ------------------ | --------- | --------- | ------- | ------- | -------- |
| time (us)          | 900.62    | 3628.9    | 4847.9  | 5840.3  | 12351    |
| throughput (MiB/s) | 1110.3232 | 275.57    | 206.27  | 171.22  | 80.964   |

