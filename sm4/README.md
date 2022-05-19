## 效率对比（128bytes）

Run on (4 X 2300 MHz CPU s)

CPU Caches:

 L1 Data 32 KiB

 L1 Instruction 32 KiB

 L2 Unified 256 KiB (x2)

 L3 Unified 4096 KiB

Load Average: 2.23, 2.25, 2.56

| Benchmark       | Time    | CPU     | Iterations |
| --------------- | ------- | ------- | ---------- |
| sm4_basic_speed | 3395 ns | 3387 ns | 1624141    |
| sm4_T_speed     | 1895 ns | 1886 ns | 2936821    |
| sm4_avx2_speed  | 369 ns  | 368 ns  | 1897112    |
| sm4_aesni_speed | 426 ns  | 425 ns  | 1644528    |

