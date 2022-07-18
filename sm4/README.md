# SM4

## Building the Code

```shell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release # Release mode
cmake .. -DCMAKE_BUILD_TYPE=Debug # Debug mode
make
```

## Efficiency（128bytes）

Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x2)
  L3 Unified 4096 KiB
Load Average: 4.44, 3.69, 3.39

| Benchmark        | Time    | CPU     | Iterations |
| ---------------- | ------- | ------- | ---------- |
| sm4_basic_speed  | 1564 ns | 1553 ns | 447997     |
| sm4_T_speed      | 918 ns  | 908 ns  | 764651     |
| sm4_avx2_speed   | 365 ns  | 363 ns  | 1928407    |
| sm4_aesni_speed  | 487 ns  | 456 ns  | 1482034    |
| sm4_avx2ni_speed | 287 ns  | 269 ns  | 2613432    |
