# tx-parser

## 1. Send a tx on Bitcoin testnet

### Step1: Get a bitcoin testnet address

We use bitcoin core[test] to generate testnet address. In this test the private key is tb1qjsl39jlanxy902jz6u505du7ejjftqjfrga6nd.
![0](/figure/0.png)

### Step2: Require bitcoin testnet coins

Require 0.0005 testnet coins to tb1qjsl39jlanxy902jz6u505du7ejjftqjfrga6nd in website <https://bitcoinfaucet.uo1.net>.
![1](/figure/1.png)
![2](/figure/2.png)

The transaction detailed can be viewed in <https://live.blockcypher.com/btc-testnet>.
![3](/figure/3.png)

<!-- ### Step3: Send coins on testnet -->

## 2. Parse tx

We parse tx based on the struct <https://en.bitcoin.it/wiki/Protocol_documentation#tx>
And to varificate correctness, we keep identical json key with <https://live.blockcypher.com/> api.

### Implementation

- ``byte2intLittle`` Convert a little-end bytcode to an integer with given length, for example ``byte2intLittle('02000000')  = 2``
- ``compactSizeParser``  As defined by <https://developer.bitcoin.org/reference/transactions.html#compactsize-unsigned-integers>, every var-int is handled by ``compactSizeParser`` method.
- ``txinParser`` parese the txin struct.
- ``txoutParser`` parese the txoutstruct.
- ``transactionParser`` parse the whole tx struct.

### Result
The example transaction is the transaction in step2. 
The detailed information: <https://api.blockcypher.com/v1/btc/test3/txs/57a01841a489d084e9e5cc1228229a344abd4c50304191b3f6e33b3a05fcb0f9?includeHex=true>
The following result is competely same as above what above website shows, except those additional computed infomation.
![tx-parser](/figure/parse.png) 
And tx-parser can also deal with other bitcion transactions bytecode.
