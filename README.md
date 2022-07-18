# SDU-2022-CryproProject
2022 Spring 创新创业实践课实践项目小组repository

队伍成员(首字母排序):
- 端木浩杰
- 刘齐
- 王泰宇
- 谢钟萱

## Project List

### SM3

- [x] Implement the naive birthday attack of reduced `SM3`

  📢OpenMP parallel computing

  📢Rust version multithreading attack with `std::thread`is done

- [x] Implement the Rho method of reduced `SM3`

- [x] Implement length extension attack for `SM3`, `SHA256`, etc.

- [x] Do your best to optimize `SM3` implementation (software)

- [x] Implement Merkle Tree following [RFC6962](https://www.rfc-editor.org/info/rfc6962)

  > Construct a Merkle tree with 10w leaf nodes
  >
  > Build inclusion proof for specified element
  >
  > Build exclusion proof for specified element  

### SM4

- [x] Do your best to optimize `SM4` implementation (software)

### SM2

- [ ] Report on the application of this deduce technique in Ethereum with `ECDSA`

- [x] Implement `SM2` with [RFC6979](https://www.rfc-editor.org/info/rfc6979)

- [ ] Verify the some pitfalls with proof-of-concept code

- [ ] Implement the above `ECMH` scheme

- [ ] Implement a `PGP` scheme with `SM2`

  > Generate session key: `SM2` key exchange  
  >
  > Encrypt session key: `SM2` encryption  
  >
  > Encrypt data: Symmetric encryption  

- [ ] Implement `SM2` 2P sign with real network communication

- [x] PoC impl of the scheme, or do implement analysis by Google

- [ ] Implement `SM2` 2P decrypt with real network communication
