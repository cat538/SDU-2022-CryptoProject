from operator import index
import common
import base58
import bech32
import binascii
from Crypto.Hash import SHA256,_RIPEMD160

class scriptParser:
    script = []
    type = "p2pkh"
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

    def scriptparser(self,bytecode):
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
    sp = scriptParser()
    bytecode = "76a914977ae6e32349b99b72196cb62b5ef37329ed81b488ac"
    #bytecode = "00148b02bddbce56f6f5abcc78a1b49dee5022a194ae"
    print(bytecode)
    sp.scriptparser(bytecode)
    sp.printScript()
    print(sp.hash160_to_address('977ae6e32349b99b72196cb62b5ef37329ed81b4'))
