import json

class txparser:
    tx = {}
    tx_in = []
    tx_out = []
    bytecode = ''
    def __init__(self):
        pass

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
        txinput['prev_hash'] = bytecode[index:index+64]
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
            witness_num,index = self.compactSizeParser(bytecode,index)
            witness = []
            for i in range(witness_num):
                witness_len,index = self.compactSizeParser(bytecode,index)
                witness_len <<= 1
                witness.append(bytecode[index:index+witness_len])
                index += witness_len
            self.tx['inputs'][0]['witness'] = witness
        
        # 6. lock time
        self.tx['lock time'] = self.byte2intLittle(bytecode,index,8)
                



if __name__ == '__main__':
    bytecode = '020000000001012f6b048c07a78c9c0a4547aaf50358c385ed664f005a1969ab0a64e17591c1630000000000feffffff0250c3000000000000160014943f12cbfd998857aa42d728fa379ecca4958249b5545401000000001600148b02bddbce56f6f5abcc78a1b49dee5022a194ae02473044022042d15e0bf80401f5b9c370e53c278c60f4a6ef264f64e0c397cc1832cf78e1aa02202ad7cd0733eda9780f2940b58b5833d046e8bc862aa5ea8074807c765d399efb0121038ded4abbb861b9d3af9ce9a4c053141007fe2e13de076ec27955ddb20cf3c4a321e32200'
    #bytecode = '020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3103935f0b04bdfed3622f466f756e6472792055534120506f6f6c202364726f70676f6c642f02007cad0000a5b9bd820300ffffffff025e0cab25000000001976a9145e9b23809261178723055968d134a947f47e799f88ac0000000000000000266a24aa21a9ed4132e09573846ceea92219f3fd4dffbe8c00dc8db14f868027e61c7bb6e0d1760120000000000000000000000000000000000000000000000000000000000000000000000000'
    
    txp = txparser()
    txp.transactionParser(bytecode)
    tx_json = json.dumps(txp.tx,indent=2)
    print(tx_json)


