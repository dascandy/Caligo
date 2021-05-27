# Caligo

Caligo exposes interfaces for varying cryptographic primitives

## Hash functions

All hash functions have a similar usage pattern. They can be used either as a one-off hash:

    std::vector<uint8_t> hash = Hash(data);

or as a hash accumulating data

    Hash hashObject;
    hashObject.add(data);
    ...
    hashObject.add(moreData);
    ...
    std::vector<uint8_t> hash = hashObject;

In the latter case the hash object can be reused for adding more data later on and getting the hash after that data was added.

The following hash functions are available:

| Hash name | Include header | Sizes implemented |
| --------- | -------------- | ----------------- |
| MD5       | caligo/md5.h   |                   |
| SHA1      | caligo/sha1.h  |                   |
| SHA2      | caligo/sha2.h  | 256, 384, 512     |
| SHA3      | caligo/sha3.h  | 256, 384, 512     |

TODO

poly1305.h

## Symmetric encryption functions

Symmetric encryption functions are nowadays only used in a variant of counter mode. As such, they only need to implement the `Encrypt` operation. Keeping track of the inputs for counter mode is left to the calling code. Currently only one algorithm is implemented - AES.

AES uses a key schedule to do encryption. Creating the key schedule is a nontrivial amount of work and as such is extracted from the Encrypt function. In an example:

    #include <caligo/aes.h>
    std::vector<uint8_t> key = {...};
    AesKeySchedule<128> keyschedule(key);
    auto encblock = AesEncrypt(keyschedule, block);

TODO

chacha20.h

## Asymmetric encryption functions

TODO

rsa.h
x25519.h

## Random number generation

random.h

## Base64 encoding

base64.h

## AEAD support functions

gcm.h
ghash.h

## Bignum library

TODO

bignum.h
mont.h

## Implementation details that can be useful

TODO

pkcs1.h
hkdf.h
key\_iv\_pair.h


