package pkcs11.jsun;

import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class Cryptography {

    /**
     * Encrypts data using AES in ECB mode with the specified token.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param hSession Handle to the PKCS#11 session associated with the token.
     * @param mechanism The encryption mechanism to use (e.g., AES ECB).
     * @param hKey Handle of the encryption key.
     * @param plaintext The data to encrypt.
     * @param ciphertext The resulting encrypted data.
     * @throws Exception If an error occurs during the encryption process.
     */
    public static void encrypt(PKCS11 p11, long hSession, CK_MECHANISM mechanism, long hKey, byte[] plaintext, byte[] ciphertext) throws Exception {
        p11.C_EncryptInit(hSession, mechanism, hKey);
        p11.C_Encrypt(hSession, 0L, plaintext, 0, plaintext.length, 0L, ciphertext, 0, ciphertext.length);
    }

    /**
     * Decrypts data using AES in ECB mode with the specified token.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param hSession Handle to the PKCS#11 session associated with the token.
     * @param mechanism The decryption mechanism to use (e.g., AES ECB).
     * @param hKey Handle of the decryption key.
     * @param ciphertext The data to decrypt.
     * @param plaintext The resulting decrypted data.
     * @throws Exception If an error occurs during the decryption process.
     */
    public static void decrypt(PKCS11 p11, long hSession, CK_MECHANISM mechanism, long hKey, byte[] ciphertext, byte[] plaintext) throws Exception {
        p11.C_DecryptInit(hSession, mechanism, hKey);
        p11.C_Decrypt(hSession, 0L, ciphertext, 0, ciphertext.length, 0L, plaintext, 0, plaintext.length);
    }

    /**
     * Generate a hash on some data.
     *
     * @param hSession handle of an open session.
     *
     * @param data data to hash from
     *
     * @param dataLen length of the data to hash
     */
    public static byte[] shaHashData(PKCS11 p11, long hSession, CK_MECHANISM hashMech,
            byte[] data,
            long dataLen) throws PKCS11Exception {

        byte[] hash = null;

        /* start the digest operation */
        p11.C_DigestSingle(hSession, hashMech, data, 0, data.length, hash, 0, data.length);

        return hash;
    }

    /**
     * Sign a hash using the ECDSA mechanism.
     *
     * @param hSession handle to an open session
     *
     * @param hPrivateKey handle of the private key to sign with
     *
     * @param hash the hash value to generate the signature from
     *
     * @param hashLen the length of the hash
     */
    static byte[] Sign(PKCS11 p11, long hSession, CK_MECHANISM signMech,
            long hPrivateKey,
            byte[] hash,
            long hashLen) throws PKCS11Exception {

        byte[] signature = null;

        /* start the sign operation */
        p11.C_SignInit(hSession, signMech, hPrivateKey);

        /* do the sign */
        signature = p11.C_Sign(hSession, hash);

        return signature;
    }

    /**
     * Hash and sign some raw data using a hashing mechanism.
     *
     * @param hSession handle to an open session
     *
     * @param hPrivateKey handle to the private key to sign with
     *
     * @param data the data to hash and sign
     *
     * @param dataLen the length of the data
     */
    static byte[] HashSign(PKCS11 p11, long hSession, CK_MECHANISM signMech,
            long hPrivateKey,
            byte[] data,
            long dataLen) throws PKCS11Exception {

        byte[] signature = null;


        /* start the sign operation */
        p11.C_SignInit(hSession, signMech, hPrivateKey);


        /* do the sign */
        signature = p11.C_Sign(hSession, data);

        return signature;
    }

    /**
     * Verify a hased signature of some raw data using the ECDSA_SHA1 mechanism.
     *
     * @param hSession handle to an open session
     *
     * @param hPublicKey public key to verify with
     *
     * @param data data to verify against
     *
     * @param dataLen length of the data to verify against
     *
     * @param signature hashed signature of the data to verify against
     *
     * @param signatureLen length of the signature
     */
    static void HashVerify(PKCS11 p11, long hSession, CK_MECHANISM verifyMech,
            long hPublicKey,
            byte[] data,
            long dataLen,
            byte[] signature,
            long signatureLen) throws PKCS11Exception {

        /* start the verify operation */
        p11.C_VerifyInit(hSession, verifyMech, hPublicKey);

        /* verify the signature against the hash */
        p11.C_Verify(hSession, data, signature);
    }

    /**
     * Verify a signature of a hash using the ECDSA mechanism.
     *
     * @param hSession handle to an open session
     *
     * @param hPublicKey public key to verify with
     *
     * @param hash hash to verify against
     *
     * @param hashLen length of the hash to verify against
     *
     * @param signature signature of the hash to verify against
     *
     * @param signatureLen length of the signature
     */
    static void Verify(PKCS11 p11, long hSession, CK_MECHANISM verifyMech,
            long hPublicKey,
            byte[] hash,
            long hashLen,
            byte[] signature,
            long signatureLen) throws PKCS11Exception {

        /* start the verify operation */
        p11.C_VerifyInit(hSession, verifyMech, hPublicKey);

        /* verify the signature against the hash */
        p11.C_Verify(hSession, hash, signature);
    }
}
