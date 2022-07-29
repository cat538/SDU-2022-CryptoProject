# SDU-2022-CryproProject

2022 Spring 创新创业实践课实践项目小组repository

队伍成员(首字母排序):

- 🦀 端木浩杰 [@cat538](https://github.com/cat538)
- 🎣 刘齐   [@lqvir](https://github.com/lqvir)
- 🐙 谢钟萱 [@0octopuS](https://github.com/0octopuS)

## 项目列表

<table>
<thead>
  <tr>
    <th align="center" width=10%> 编号</th>
    <th width=55%>项目名称</th>
    <th width=25%>对应文件夹</th>
    <th width=10%>完成人</th>
  </tr>
</thead>
<tbody>
   <tr>
    <td align="center" colspan="4"> 
        ✅已完成
    </td> 
   </tr>
  <tr>
    <td rowspan="2" align="center"> 1</td>
    <td rowspan="2" >implement the naïve birthday attack of reduced <code>SM3</code>
    <li> 📢 OpenMP parallel computing
    <li> 📢 Rust version multithreading attack with std::threadis done
    </td>
    <td><a href="./sm3/sm3-collision/cpp-naive-rho">cpp-naive-rho</a>
    </td>
    <td align="center">🎣</td>
  </tr>
<tr>
    <td><a href="./sm3/sm3-collision/rust-naive-rho">rust-naive-rho</a></td>
    <td align="center">🦀 </td>
  </tr>
  <tr>
    <td rowspan="2" align="center"> 2</td>
    <td rowspan="2" >implement the Rho method of reduced <code>SM3</code></td>
    <td><a href="./sm3/sm3-collision/cpp-naive-rho">cpp-naive-rho</a></td>
    <td align="center">🎣</td>
  </tr>
  <tr>
    <td><a href="./sm3/sm3-collision/rust-naive-rho">rust-naive-rho</a></td>
    <td align="center"> 🦀</td>
  </tr>
  <tr>
    <td align="center">3</td>
    <td>implement length extension attack for <code>SM3</code>, <code>SHA256</code>, etc</td>
    <td><a href="./sm3/md-length-extension-attack">md-length-extension-attack</a></td>
    <td align="center">🐙</td>
  </tr>
  <tr>
    <td rowspan="2" align="center">4</td>
    <td rowspan="2" >do your best to optimize <code>SM3</code> implementation (software)</td>
    <td><a href="./sm3/sm3-impl/sm3-cpp">sm3-cpp</a></td>
    <td align="center">🐙</td>
  </tr>
    <td><a href="./sm3/sm3-impl/rust-naive-optimised">rust-naive-optimised</a></td>
    <td align="center">🦀</td>
  <tr>
  </tr>
  <tr>
    <td rowspan="3" align="center">5</td>
    <td rowspan="3" >Impl Merkle Tree following 
    <a herf="https://www.rfc-editor.org/info/rfc6962"> RFC6962 </a>
    <blockquote> 
         <li> Construct a Merkle tree with 10w leaf nodes
         <li> Build inclusion proof for specified element
         <li> Build exclusion proof for specified element
     </blockquote>
    </td>
    <td><a href="./merkle-tree/merkle-impl/merkle-tree-impl-cpp">merkle-tree-impl-cpp</a></td>
    <td align="center">🎣</td>
  </tr>
  <tr>
    <td> <a href="./merkle-tree/merkle-impl/merkle-tree-impl-go">merkle-tree-impl-go</a></td>
    <td align="center"> 🐙</td>
  </tr>
  <tr>
    <td> <a href="./merkle-tree/merkle-impl/merkle-tree-impl-rust">merkle-tree-impl-rust</a></td>
    <td align="center">🦀 </td>
  </tr>
  <tr>
    <td align="center">7</td>
    <td>report on the application of this deduce technique in Ethereum with <code>ECDSA</code></td>
    <td><a href="./sm2/ecdsa-pk-recovery.md" >ecdsa-pk-recovery</a></td>
    <td align="center">🦀</td>
  </tr>
  <tr>
    <td rowspan="2" align="center">8</td>
    <td rowspan="2">impl <code>sm2</code> with <a herf="https://www.rfc-editor.org/info/rfc6980"> RFC6979 </a></td>
    <td><a href="./sm2/sm2-impl-go" target="_blank" rel="noopener noreferrer">sm2-go</a></td>
    <td align="center">🐙</td>
  </tr>
  <tr>
    <td ><a href="./sm2/sm2-impl-rust">sm2-rust</a></td>
    <td align="center">🦀</td>
  </tr>
  <tr>
    <td align="center">9</td>
    <td>verify the above pitfalls with proof-of-concept code</td>
    <td><a href="./sig-pitfall">sig-pitfall</a></td>
    <td align="center">🐙</td>
  </tr>
  <tr>
    <td align="center">10</td>
    <td>Implement the above <code>ECMH</code> scheme</td>
    <td><a href="./ecmh">ecmh</a></td>
    <td align="center">🐙</td>
  </tr>
  <tr>
    <td rowspan="2" align="center">11</td>
    <td rowspan="2" >Implement a <code>PGP</code> scheme with <code>SM2</code>
    <blockquote> 
         <li> Generate session key: SM2 key exchange
         <li> Encrypt session key: SM2 encryption
         <li> Encrypt data: Symmetric encryption
     </blockquote>
    </td>
    <td><a href=./sm2/sm2-pgp-cpp>sm2-pgp-cpp</a></td>
    <td align="center">🎣</td>
    
  </tr>
  <tr>
    <td><a href="./sm2/sm2-pgp-go">sm2-pgp-go</a></td>
    <td align="center">🐙</td>
  </tr>
  <tr>
    <td align="center">12</td>
    <td>implement <code>sm2</code> 2P sign with real network communication</td>
    <td><a href="./sm2/sm2-applied">sm2-applied</a></td>
    <td align="center">🦀️</td>
  </tr>
  <tr>
    <td align="center">13</td>
    <td>implement <code>sm2</code> 2P decrypt with real network communication</td>
    <td><a href="./sm2/sm2-applied" >sm2-applied</a></td>
    <td align="center">🦀️</td>
  </tr>
  <tr>
    <td align="center">14</td>
    <td>PoC impl of the scheme, or do implement analysis by Google</td>
    <td > <a href="./poc-of-zkp">poc-of-zkp</a></td>
    <td align="center">🎣</td>
  </tr>
  <tr>
    <td align="center">15</td>
    <td>send a tx on Bitcoin testnet, and parse the tx data down to every bit, better write script yourself</td>
    <td><a href="./tx-parser">tx-parser</a></td>
    <td align="center">🐙</td>
  </tr>
  <tr>
    <td align="center">16</td>
    <td>forge a signature to pretend that you are Satoshi</td>
    <td> <a href="./faketoshi">faketoshi</a></td>
    <td align="center">🐙</td>
  </tr>
  <tr>
    <td align="center">17</td>
    <td>research report on MPT</td>
    <td> <a href="./merkle-tree/MPT%20report.md"> MPT report</a></td>
    <td align="center">🦀️</td>
  </tr>
  <tr>
    <td align="center">20</td>
    <td>Try to build zkp app to proof CET6 Score &gt; 425</td>
    <td><a href="./poc-of-zkp">poc-of-zkp</a></td>
    <td align="center">🎣</td>
  </tr>
  <tr>
    <td align="center">额外</td>
    <td>  Do your best to optimize <code>SM4</code> implementation (software)
</td>
    <td><a href="./sm4">sm4</a></td>
    <td align="center">🐙</td>
  </tr>
  <tr>
    <td align="center" colspan="4"> 
        ❌未完成
    </td> 
   </tr>
  <tr>
    <td align="center">6</td>
    <td>Try to Implement this scheme(below)</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td align="center">18</td>
    <td>Find a key with hash value “sdu_cst_20220610” under a message composed of your name followed by your student ID. For example, “San Zhan 202000460001”.</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td align="center">19</td>
    <td>Find a 64-byte message under some k fulfilling that their hash value is symmetrical.</td>
    <td></td>
    <td></td>
  </tr>
</tbody>
</table>
