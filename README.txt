WSNTP (What's Signed On The Picture?) is a picture signing tool running in the cmd lines.

The workflow
|----------------------------|             |----------------------------|             |----------------------------|
|                            |             |  Use the private key to    |             |                            |
|  Create public and secret  |             |  sign something in the     |             |   Use the public key to    |
|  keys, and stored in       | ----------> |  picture. The public key   | ----------> |   get the sign in the      |
|  ~/.wsntp .                |             |  is stored in picture at   |             |   picture.                 |
|                            |             |  the same time.            |             |                            |
|----------------------------|             |----------------------------|             |----------------------------|


Embed (wsntp embed)
  Image + Private Key + Message
->Derive public key from private key
->Public key acts as PRNG seed -> Determine which FFT coefficients to modify
->Sign (PubKey || MsgLen || Message) with private key -> Ed25519 signature (64B)
->Build payload: [Magic 4B][Version 1B][Reserved 1B][Public Key 32B][Signature 64B][Message Length 2B][Message UTF-8]
->Block-wise FFT -> QIM quantization embedding -> Hermitian symmetry fix -> Inverse FFT -> Output image

Extract (wsntp extract)
  Image + Public Key
->Public key acts as PRNG seed -> Determine which FFT coefficients to read
->Block-wise FFT -> Read QIM bits -> Decode payload
->Verify: Ed25519 verify(embedded_pubkey, PubKey||MsgLen||Message, embedded_signature)
->Verify fails -> image tampered, reject
->Compare: embedded_pubkey == user_provided_pubkey
->Mismatch -> not your signature, reject
->Return message


Payload Format

|---------|-----------|-------|--------------------------------------------------|
| Offset  | Field     | Size  | Description                                      |
|---------|-----------|-------|--------------------------------------------------|
| 0-3     | magic     | 4 B   | b"WSNT" for detection                            |
|---------|-----------|-------|--------------------------------------------------|
| 4       | version   | 1 B   | 0x01                                             |
|---------|-----------|-------|--------------------------------------------------|
| 5       | reserved  | 1 B   | 0x00                                             |
|---------|-----------|-------|--------------------------------------------------|
| 6-37    | pubkey    | 32 B  | Ed25519 public key (also PRNG seed)              |
|---------|-----------|-------|--------------------------------------------------|
| 38-101  | signature | 64 B  | Ed25519 signature over (pubkey||msg_len||msg)    |
|---------|-----------|-------|--------------------------------------------------|
| 102-103 | msg_len   | 2 B   | Message byte length (big-endian)                 |
|---------|-----------|-------|--------------------------------------------------|
| 104+    | message   | N B   | UTF-8 message                                    |
|---------|-----------|-------|--------------------------------------------------|

