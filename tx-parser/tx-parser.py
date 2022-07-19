import json
from Crypto.Hash import SHA256
import binascii
 
class txParser:
    tx = {}
    tx_in = []
    tx_out = []
    bytecode = ''
    def __init__(self):
        pass

    def sha256d(self,st):
        hash = SHA256.new()
        hash.update(st)
        return hash.digest()

    def byte2intLittle(self,bytecode,index,num):
        temp = bytes.fromhex(bytecode[index:index+num])[::-1]
        temp = int.from_bytes(temp,"big")
        return temp

    def compactSizeParser(self,bytecode,index):
        size = int(bytecode[index:index+2],16)
        index += 2
        if size == 0xfd:
            return self.byte2intLittle(bytecode,index,4),index+4
        elif size == 0xfe:
            return self.byte2intLittle(bytecode,index,6),index+6
        elif size == 0xff:
            return self.byte2intLittle(bytecode,index,16),index+16
        else:
            return int(bytecode[index-2:index],16),index
            

    def txinParser(self,bytecode,index):
        txinput = {}
        # 3.1 Get previous_output hash 
        # txinput['prev_hash'] = bytecode[index:index+64][::-1]
        txinput['prev_hash'] = hex(self.byte2intLittle(bytecode,index,64))[2:]
        index += 64
        
        # 3.2 Get previous_output index
        txinput['output_index'] =  self.byte2intLittle(bytecode,index,8);
        index += 8

        # 3.3 Get script length
        script_len = self.byte2intLittle(bytecode,index,2) << 1;
        index += 2

        # 3.4 Get script
        txinput['script'] = bytecode[index:index+script_len];
        index += script_len

        # 3.5 Get sequence
        txinput['sequence'] = self.byte2intLittle(bytecode,index,8);
        index += 8


        self.tx_in.append(txinput)
        return index
        
    def txoutParser(self,bytecode,index):
        txoutput = {}
        # 4.1 value
        txoutput['value'] = self.byte2intLittle(bytecode,index,16)
        index += 16

        # 4.2 pk_script length	
        pk_len,index = self.compactSizeParser(bytecode,index)
        pk_len <<= 1

        # 4.3 pk_script
        txoutput['script'] = bytecode[index:index + pk_len]
        index += pk_len
        self.tx_out.append(txoutput)
        return index


    def transactionParser(self,bytecode):
        txid = bytecode
        index = 0
        # 1. version
        self.tx["version"] = self.byte2intLittle(bytecode,index,8)
        index += 8

        # 2.(optional) flag
        if(bytecode[index:index+4] == '0001'):
            self.tx["flag"] = 'True'
            index += 4
        
        
        # 3. txin
        vin_num,index = self.compactSizeParser(bytecode,index)
        self.tx['vin_sz'] = vin_num
        for i in range(vin_num):
            index = self.txinParser(bytecode,index)
        self.tx['inputs']  = self.tx_in
 
        # 4. txout

        vout_num,index = self.compactSizeParser(bytecode,index)
        self.tx['vout_sz'] = vout_num
        for i in range(vout_num):
            index = self.txoutParser(bytecode,index)
        self.tx['outputs']  = self.tx_out

        # 5.(optional) witness
        if "flag" in self.tx:
            txid1 = txid[0:index]
            witness_num,index = self.compactSizeParser(bytecode,index)
            witness = []
            for i in range(witness_num):
                witness_len,index = self.compactSizeParser(bytecode,index)
                witness_len <<= 1
                witness.append(bytecode[index:index+witness_len])
                index += witness_len
            self.tx['inputs'][0]['witness'] = witness
            txid2 = txid[index:] # remove witness
            txid = txid1 + txid2
            txid = txid[0:8] + txid[12:] # remove optional flag
        

        # 6. lock time
        self.tx['lock time'] = self.byte2intLittle(bytecode,index,8)

        # 7.(additional) hash
        txid = self.sha256d(self.sha256d(bytes.fromhex(txid))) # get double sha256 hash result
        txid = binascii.hexlify(txid[::-1]).decode() # get reverse hash hex result
        self.tx['hash'] = txid
                



if __name__ == '__main__':
    bytecode = '020000000001012f6b048c07a78c9c0a4547aaf50358c385ed664f005a1969ab0a64e17591c1630000000000feffffff0250c3000000000000160014943f12cbfd998857aa42d728fa379ecca4958249b5545401000000001600148b02bddbce56f6f5abcc78a1b49dee5022a194ae02473044022042d15e0bf80401f5b9c370e53c278c60f4a6ef264f64e0c397cc1832cf78e1aa02202ad7cd0733eda9780f2940b58b5833d046e8bc862aa5ea8074807c765d399efb0121038ded4abbb861b9d3af9ce9a4c053141007fe2e13de076ec27955ddb20cf3c4a321e32200'
    #bytecode = '0100000001f7d7667421677ae9bce69e558048e0aca48d704c1dc446cdec80c5e77df7c124000000008b483045022100b92b0d78a1a72b25179260e96a15efe95f98962622fb232f92d6c6ef20e15e9b022061c946c3f976339e370eabd256d91aa4711bb9985330f7d18ee77987b0ca24300141046c04c02f1138f440e8c5e9099db938bfba93d0389528bb7f6bf423ae203a2edcfba133f0409023d7ea13ac01c5aeedaf0bbfbeb8b82e9b48410d93a296da5b0cffffffff0100f2052a010000001976a914e6a874331cddf113e6f424f547aa93c10755d5e688ac00000000'
    #bytecode = '02000000000101f9b0fc053a3be3f6b3914130504cbd4a349a222812cce5e984d089a44118a0570000000000fdffffff0230750000000000001976a914868cdc1f4536a6a583072952d752899aa032036d88ac734c000000000000160014956fa48309577f3d3be4aeec1987932345ba290002473044022025261e38cc67990ab5b0b05e6223993b326261856cc8f2b7e89438452fc81477022065cf9d4436508c77a3d7ad19e5abb388da7b88772e430d11779af782a6c80d39012103c77102d671e80edfb925d9021a2a9a8f57af1a415f49902fcfcf06e885a9e1c068e42200'
    txp = txParser()
    txp.transactionParser(bytecode)
    tx_json = json.dumps(txp.tx,indent=2)
    print(tx_json)


