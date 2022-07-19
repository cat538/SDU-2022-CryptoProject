from operator import index
import common
import base58
import bech32
import binascii
from Crypto.Hash import SHA256,_RIPEMD160

class scriptPaser:
    script = []
    type = "bech32"
    prefixes = {
        "p2pkh": '00',         # 1address - For standard bitcoin addresses
        "p2sh":  '05',         # 3address - For sending to an address that requires multiple signatures (multisig)
        "p2pkh_testnet": '6F', # (m/n)address
        "p2sh_testnet":  'C4' , # 2address
        "bech32": '04358394',
    }
    

    def hash160(self,bytecode):
        hash = SHA256.new()
        hash2 = _RIPEMD160.new()
        hash.update(bytes.fromhex(bytecode))
        hash2.update(hash.digest())
        return binascii.hexlify(hash2.digest()[::-1]).decode()
    
    def checksum(self,bytecode):
        hash = SHA256.new()
        hash2 = SHA256.new()
        hash.update(bytes.fromhex(bytecode))
        hash2.update(hash.digest())
        return binascii.hexlify(hash2.digest()).decode()[:8]

    def hash160_to_address(self,hash):
        prefix = self.prefixes[self.type]
        checksum = self.checksum(prefix + hash)
        address = base58.b58encode(bytes.fromhex(prefix + hash + checksum))
        return address

    def scriptpaser(self,bytecode):
        index = 0
        length = len(bytecode)
        while index < length:
            opcode = int(bytecode[index:index+2],16)
            index +=2
            if opcode == 0:
                pass
            elif opcode in common.VALID_OPCODES:
                self.script.append(common.OPCODE_NAMES[opcode])
            else :
                self.script.append(bytecode[index:index+opcode*2])
                index += opcode*2

    def printScript(self):
        print(self.script)



if __name__ == '__main__':
    sp = scriptPaser()
    #bytecode = "76a914977ae6e32349b99b72196cb62b5ef37329ed81b488ac"
    #bytecode = "00148b02bddbce56f6f5abcc78a1b49dee5022a194ae"
    bytecode ="02000000000101f9b0fc053a3be3f6b3914130504cbd4a349a222812cce5e984d089a44118a0570000000000fdffffff0230750000000000001976a914868cdc1f4536a6a583072952d752899aa032036d88ac734c000000000000160014956fa48309577f3d3be4aeec1987932345ba290002473044022025261e38cc67990ab5b0b05e6223993b326261856cc8f2b7e89438452fc81477022065cf9d4436508c77a3d7ad19e5abb388da7b88772e430d11779af782a6c80d39012103c77102d671e80edfb925d9021a2a9a8f57af1a415f49902fcfcf06e885a9e1c068e42200"
    sp.scriptpaser(bytecode)
    sp.printScript()
