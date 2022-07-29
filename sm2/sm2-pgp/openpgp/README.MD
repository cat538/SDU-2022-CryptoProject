# OpenPGP-sm2

## Discription

This project aim at modifiying [openpgp](https://pkg.go.dev/golang.org/x/crypto/openpgp) in evety aspects, generating a practical sm2-pgp scheme can be used in reality.

The tricky part is most of orginal work in [openpgp](https://pkg.go.dev/golang.org/x/crypto/openpgp) depend on golang standard library [crypto](https://pkg.go.dev/crypto), which doesn't support any ``sm`` scheme. So we try to change all the possible part.

This modified ``openpgp`` now can :

- generate\parse sm2 private key and public key.
- generate\parse  sm2 signature.
- generate\parese entity with sm2 public key algorithm.
- send sm2-publickey packet.
- send sm2-encrypt session key packet.
- send cipher text packet, encrypted by AES128, but using sm2-encrypt session key.

## Change parts

- packet/encrypt_key.go

  ```go
  - func (e *EncryptedKey) parse(r io.Reader) (err error) <= adding case PubKeyAlgoSM2
  - func SerializeEncryptedKey(w io.Writer, pub *PublicKey, cipherFunc CipherFunction, key []byte, config *Config) error <= adding case PubKeyAlgoSM2
  - func serializeEncryptedKeySM2(w io.Writer, rand io.Reader, header [10]byte, pub *sm2.PublicKey, keyBlock []byte) error
  ```

- packet/packet.go
  
  ```go
  - var PubKeyAlgoSM2
  - func (pka PublicKeyAlgorithm) CanSign()/CanEncrypt() bool  <= adding case PubKeyAlgoSM2
  - const CipherSM4
  - func (cipher CipherFunction) KeySize() int <= adding case CipherSM4
  - func (cipher CipherFunction) blockSize() int  <= adding case CipherSM4
  - func (cipher CipherFunction) new(key []byte) (block cipher.Block) <= adding case CipherSM4
  ```
  
- packet/private_key.go

  ```go
  - func NewSM2PrivateKey
  - func NewSignerPrivateKey(creationTime time.Time, signer crypto.Signer) *PrivateKey <= adding case PubKeyAlgoSM2
  - func (pk *PrivateKey) Serialize(w io.Writer) (err error) <= adding case PubKeyAlgoSM2
  - func serializeSM2PrivateKey(w io.Writer, priv *sm2.PrivateKey) error
  - func (pk *PrivateKey) parsePrivateKey(data []byte) (err error) <= adding case PubKeyAlgoSM2
  - func (pk *PrivateKey) parseSM2PrivateKey(data []byte) (err error)
  ```

- packet/private_key_test.go

  ```go
  - func TestSM2SignerPrivateKey(t *testing.T)
  - func TestSM2PrivateKey(t *testing.T)
  ```

- packet/public_key.go

  ```go
  - type PublicKey  <= adding ecsm2 *sm2Key
  - var oidCurveSm2
  - type sm2Key struct
  - func (f *sm2Key) parse(r io.Reader) (err error)
  - func (f *sm2Key) serialize(w io.Writer) (err error)
  - func (f *sm2Key) newSM2() (*sm2.PublicKey, error)
  - func (f *sm2Key) byteLen() int
  - func (pk *PublicKey) parse(r io.Reader) (err error) <= adding case PubKeyAlgoSM2
  - func (pk *PublicKey) SerializeSignaturePrefix(h io.Writer)  <= adding case PubKeyAlgoSM2
  - func (pk *PublicKey) Serialize(w io.Writer) (err error)  <= adding case PubKeyAlgoSM2
  - func (pk *PublicKey) serializeWithoutHeaders(w io.Writer) (err error) <= adding case PubKeyAlgoSM2
  - func (pk *PublicKey) VerifySignature(signed hash.Hash, sig *Signature) (err error)  <= adding case PubKeyAlgoSM2
  ```

- packet/public_key_test.go

  ```go
  - func TestSM2KeyID(t *testing.T)
  ```

- packet/signature.go

  ```go
  - type Signature struct <= adding SM2SigR, SM2SigS     parsedMPI
  - func (sig *Signature) parse(r io.Reader) (err error) <= adding case PubKeyAlgoSM2
  - func (sig *Signature) Sign(h hash.Hash, priv*PrivateKey, config *Config) (err error)  <= adding case PubKeyAlgoSM2
  - func unwrapSM2Sig(b []byte) (r, s *big.Int, err error)
  - func (sig *Signature) Serialize(w io.Writer) (err error) <= adding case PubKeyAlgoSM2
  ```

- key.go

  ```go
  - func NewEntitySM2(name, comment, email string, config *packet.Config) (*Entity, error)
  ```

## Test Results

- ``func TestSM2SignerPrivateKey``
   Target function:  ``NewSignerPrivateKey(time.Now(), &sm2Signer{sm2Priv}) <= case PubKeyAlgoSM2``
                     ``TestSM2SignerPrivateKey``
   Usage: Generating new SM2 Private Key.
![1](./figure/TestSM2SignerPrivateKey.png)

- ``func TestGenEncKeySM2(t *testing.T)``
  Target function: ``serializeEncryptedKeySM2``
  Usage: Encrypt session key using sm2 encryption scheme.
![2](./figure/TestGenEncKeySM2.png)

- ``func TestNewEntitySM2``
 Target function: ``NewEntitySM2``
 Usage: Generating a new Entity with SM2 Private Key.
  ![3](./figure/NewEntitySM2.png)
