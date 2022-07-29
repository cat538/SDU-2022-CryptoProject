# ECDSA Public Key Recovery

椭圆曲线用6元组表示：$T=(p,a,b,G,n,h)$；其中素数$p$为$\mathbb{F}_p$的阶，$a,b$为曲线的系数，$G$为生成元，$n$为阶，$h$为co-factor

## ECDSA

- 密钥对：$(Q,d)$，其中$Q = d\cdot G$
- 签名：
  1. 选择$k\in [1,n-1]$
  2. 计算$P = (x,y)=k\cdot G$，$r=x\mod n$，若$r=0$，回到第1步
  3. 计算消息摘要$e=H(m)$
  4. 计算$s=k^{-1}(e+dr)\mod n$，若$s=0$，回到第一步
  5. 输出$(r,s)$；**注意到有**：$k=s^{-1}(e+dr)$，因此$k\cdot G = s^{-1}(e+dr)\cdot G=s^{-1}(e\cdot G+r\cdot Q)$
- 验签：
  1. 检验$r,s$是否处于$[1,n-1]$
  2. 计算消息摘要$e=H(m)$
  3. 计算$w=s^{-1}\mod n$
  4. 计算$u_1 = es^{-1},u_2 = rs^{-1}$
  5. 计算$X(x_1,y_1)=u_1G+u_2Q$；**合法性**：$s^{-1}(eG+rdG)=s^{-1}(e+dr)G=kG=P$
  6. 若$X=0$，拒绝；否则计算$v = x_1$，若$v=r$，接受

## Public Key Recovery

**输入**：椭圆曲线$T$（六元组表示）；消息$m$；对于消息$m$的ECDSA签名$(r,s)$

**输出**：可以对于消息$m$和签名$(r,s)$，正确验签的公钥$Q$（曲线上的点）

$$
\begin{align*}
Q &= r^{-1}(sP-eG)\\
&=r^{-1}(k^{-1}(e+dr)kG-eG)\\
&=r^{-1}((e+dr)G-eG)\\
&=dG
\end{align*}
$$

因此在已知签名$(r,s)$以及$e=h(m)$的情况下，如果知道$P=kG$，就可以恢复签名公钥。但是我们不知道$P$，我们只知道$r=x\mod n$，其中$x\in [1,p]$为$P$的横坐标。一般来说$n$是小于$p$不太多的数，因此一个$r$可能对应两个$x$：

- 如果 $r < p - n $，则$x=r$ 或 $x=r+n$
- 如果 $r>p-n$，则$x=r$

> But note that the case of two possible X coordinates for a single $r$ is very rare; indeed, this will happen randomly **with probably about** $2^{−128}$, i.e. never in practice (although you might be able to force it with specially crafted data). 

不过我们在确定了$P$的横坐标$x$后，一个横坐标$x$对应两个曲线上的点$P_1$和$P_2$，两者纵坐标互为相反数，而$P_1$和$P_2$都能验签(如下所示)。因此对于一个签名，理论上至多有4个可能正确验签的公钥$Q'$

$$
\begin{align*}
X &= u_1G+u_2Q'&\\
&=s^{-1}eG+rs^{-1}Q'\\
&=s^{-1}eG+rs^{-1}r^{-1}(sP'-eG)\\
&=P'=(x,y')
\end{align*}
$$

签名方附加一些额外辅助信息可以使验证方完成唯一的公钥恢复，节省传输公钥的带宽。但是需要注意，无效的签名或来自不同消息的签名将导致恢复出一个不正确的公钥；只有在签名者的公钥(或其散列)事先已知的情况下，恢复算法才能用于检查签名的有效性。

> [参考资料]
>
> - [Recovery public key from secp256k1 signature and message - Cryptography Stack Exchange](https://crypto.stackexchange.com/questions/60218/recovery-public-key-from-secp256k1-signature-and-message)
> - [Elliptic Curve Digital Signature Algorithm - Wikipedia](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
