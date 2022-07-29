# md-length-extension-attack

## Building the Code

```shell
mkdir build
cd build
cmake ..
make
./../out/lea
```

## Description

``class LEA`` define the basic  information. And class ``SM3LEA`` and ``SHA256LEA`` inherit from ``LEA``, and define the length extension attack in their constructor functions. The implementation of sm3 is from our project ``sm3-cpp``. The attack is accoring to ``MD5(IV, salt+data+padding+append) = MD5(MD5(IV, salt+data), append)``.

### Step1. Make New Block

If the keylen is leaked, we can padding the block to a block size using ``0x00``.

```cpp
for(auto& x: orig) { new_msg -> push_back(x);} 
int tail_len = (new_msg->size() + keylen) << 3; // 8倍
new_msg -> push_back(0x80);
for(int i = (new_msg->size() + keylen + 8) % 64; i < 64 + 4; i++) 
    { new_msg -> push_back(0x00); }
```

### Step2. Extend length info

```cpp
for(int i = 3; i >= 0; i-- )
  { new_msg -> push_back( (tail_len >> (i << 3)) & 0xff ); }
```

### Step3. Hash Original data

```cpp
 for(int i = 0; i < 8; i ++){
  new_sig_ctx.h[i] = 0;
  for(int j = 0; j < 4; j ++){
   // eg: i = 0 : h[0] << 24 ; h[1] << 16; h[2] << 8; h[1] << 0;
   new_sig_ctx.h[i] |=  (orig_hash[(i << 2) + j] << ((3 - j) << 3)) ; 
  }
 }
```

### Step4. Hash Append Msg

```cpp
for(auto& x:add) new_msg -> push_back(x);
 char* buf = new char[add.size()];
 memcpy(&buf,&add,add.size());
 SM3_Update(&new_sig_ctx,buf,add.size());
```


## Result
![1](./out/lea.png)