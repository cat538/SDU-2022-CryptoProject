## 说明

- 依赖benchmark进行效率测试 https://github.com/google/benchmark

## 效率对比

Run on (4 X 2300 MHz CPU s)

CPU Caches:

 L1 Data 32 KiB

 L1 Instruction 32 KiB

 L2 Unified 256 KiB (x2)

 L3 Unified 4096 KiB

Load Average: 2.23, 2.25, 2.56

| Benchmark       | Time   | CPU    | Iterations |
| --------------- | ------ | ------ | ---------- |
| sm4_basic_speed | 441 ns | 431 ns | 1624141    |
| sm4_T_speed     | 243 ns | 238 ns | 2936821    |
|                 |        |        |            |