package pkcs11.jsun;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class ManageObjects {

    /**
     * Searches for a key on a token matching the provided template.
     *
     * This method initializes the search for objects matching the specified template
     * (which could represent key attributes) and returns the handle of the first object 
     * found that meets the criteria.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to the open PKCS#11 session associated with the token.
     * @param template Cryptoki template with the desired key attributes (e.g., key class, type, label).
     * @return The handle of the first key found that matches the provided template.
     * @throws Exception If no key is found matching the template.
     */
    public static long find(PKCS11 p11, long hSession, CK_ATTRIBUTE[] template) throws Exception {

        long[] hKeys;

        // Initialize the object search using the provided template.
        p11.C_FindObjectsInit(hSession, template);
        hKeys = p11.C_FindObjects(hSession, 1);  // Only looking for one key.
        p11.C_FindObjectsFinal(hSession);  // Finalize the search.

        // Return the first key found, or throw an exception if no key is found.
        if (hKeys.length >= 1) {
            return hKeys[0];
        } else {
            throw new Exception("Key not found!");
        }
    }

    /**
     * Deletes a specified key from the token.
     *
     * This method destroys a key object identified by the handle, effectively removing it from the token.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to the open PKCS#11 session associated with the token.
     * @param hKey The handle of the key to be destroyed.
     * @throws PKCS11Exception If an error occurs during the key destruction process.
     */
    public static void delete(PKCS11 p11, long hSession, long hKey) throws PKCS11Exception{
        p11.C_DestroyObject(hSession, hKey);
    }

    /**
     * Derives a new cryptographic key based on a provided base key using the specified mechanism.
     *
     * This method uses a cryptographic mechanism (e.g., a key derivation function) to generate 
     * a new key from the base key. The new key's attributes are defined by the provided template.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to the open PKCS#11 session associated with the token.
     * @param mechanism The cryptographic mechanism used for key derivation (e.g., `CKM_KEY_DERIVATION`).
     * @param hBaseKey The handle of the base key used for the derivation.
     * @param newObjTpl The template for the new derived key's attributes.
     * @return The handle of the newly derived key.
     * @throws PKCS11Exception If an error occurs during the key derivation.
     */
    public static long deriveKey(PKCS11 p11, long hSession, CK_MECHANISM mechanism, long hBaseKey, CK_ATTRIBUTE[] newObjTpl) throws PKCS11Exception {
        return p11.C_DeriveKey(hSession, mechanism, hBaseKey, newObjTpl);
    }

    /**
     * Wraps a key using another key with a specified mechanism.
     *
     * This method wraps (encrypts) the specified key using a wrapping key and a cryptographic
     * mechanism (e.g., AES in ECB mode). The result is a wrapped key that can be securely
     * transferred or stored.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to the open PKCS#11 session associated with the token.
     * @param mechanism The mechanism used for wrapping (e.g., AES ECB).
     * @param wrappingKey Template containing attributes to identify the wrapping key.
     * @param keyToWrap Template containing attributes to identify the key to be wrapped.
     * @return The wrapped key as a byte array.
     * @throws Exception If an error occurs during the key wrapping process.
     */
    public static byte[] wrapKey(PKCS11 p11, long hSession, CK_MECHANISM mechanism, CK_ATTRIBUTE[] wrappingKey, CK_ATTRIBUTE[] keyToWrap) throws Exception {
        long hWrappingKey = find(p11, hSession, wrappingKey);  // Locate the wrapping key.
        long hKeyToWrap = find(p11, hSession, keyToWrap);  // Locate the key to be wrapped.
        return p11.C_WrapKey(hSession, mechanism, hWrappingKey, hKeyToWrap);
    }

    /**
     * Generates an asymmetric key pair.
     *
     * This method generates both a public and private key pair, using the provided key generation
     * mechanism and attribute templates. The generated keys are returned as handles.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to the open PKCS#11 session associated with the token.
     * @param keyGenMech The key generation mechanism to use (e.g., RSA, EC).
     * @param publicTemplate Template for the public key's attributes.
     * @param privateTemplate Template for the private key's attributes.
     * @param hPublicKey Output parameter: Handle for the generated public key.
     * @param hPrivateKey Output parameter: Handle for the generated private key.
     * @throws PKCS11Exception If an error occurs during key pair generation.
     */
    public static void generateKeyPair(PKCS11 p11, long hSession, CK_MECHANISM keyGenMech, CK_ATTRIBUTE[] publicTemplate, CK_ATTRIBUTE[] privateTemplate,
            long hPublicKey,
            long hPrivateKey) throws PKCS11Exception {

        long[] keys = p11.C_GenerateKeyPair(hSession, keyGenMech,
                publicTemplate,
                privateTemplate);

        hPublicKey = keys[0];
        hPrivateKey = keys[1];
    }

    /**
     * Generates a symmetric key using a specified mechanism.
     *
     * This method generates a symmetric key (e.g., AES, DES) based on the specified mechanism type
     * and attribute template. The key is either public or private depending on the attributes in
     * the template.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param session Handle to the open PKCS#11 session associated with the token.
     * @param template Template for the key's attributes (e.g., label, usage, etc.).
     * @param mechanismType The mechanism to use for generating the key (e.g., `CKM_AES_KEY_GEN`).
     * @param keyName The name (label) to assign to the generated key.
     * @param bPrivate If true, the key is generated as a private object.
     * @return The handle of the generated symmetric key.
     * @throws PKCS11Exception If an error occurs during key generation.
     */
    public static long generateKey(PKCS11 p11, long session, CK_ATTRIBUTE[] template,
            long mechanismType,
            String keyName,
            boolean bPrivate) throws PKCS11Exception {
        CK_MECHANISM keyGenMech = new CK_MECHANISM(mechanismType);

        return p11.C_GenerateKey(session, keyGenMech, template);
    }
}
