# PKCS#11

[PKCS#11](https://www.cryptsoft.com/pkcs11doc/) (Public-Key Cryptography Standard #11) is a platform-independent API standard for managing or using cryptographic tokens such as smartcards, HSMs (Hardware Security Modules), SSMs (Software Security Modules), and other security modules. For this usage, PKCS#11 is also called the Cryptographic Token Interface (Cryptoki).

It defines a set of functions that applications can use to interact with secure elements, enabling secure key storage, digital signatures, and encryption/decryption operations.

PKCS#11 was first developed and maintained by RSA Labs from 1995 to 2009. Currently, PKCS#11 is maintained by the [OASIS committee](https://groups.oasis-open.org/communities/tc-community-home-new?CommunityKey=000035465). The different versions of the standard are available at the [PKCS-DOC](https://www.cryptsoft.com/pkcs11doc/) website:

- **V2.20** has been widely used and implemented by multiple token vendors.
- **V2.30** is still a draft.
- **V2.40** is the first published version by OASIS.
