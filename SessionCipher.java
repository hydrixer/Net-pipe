import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionCipher {

    private final Cipher mycipher;
    private final byte[] iv;
    SessionKey mykey;
    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        mycipher= Cipher.getInstance("AES/CTR/NoPadding");
        mycipher.init(1, key.getSecretKey());
        iv = mycipher.getIV();
        mykey=key;
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        mycipher= Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec param1 = new IvParameterSpec(ivbytes);
        mycipher.init(1, key.getSecretKey(),param1);
        iv=ivbytes;
        mykey=key;
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return mykey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return iv;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(mykey.getKeyBytes(),"AES"), new IvParameterSpec(iv));
        return new CipherOutputStream(os, cipher);
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(mykey.getKeyBytes(),"AES"), new IvParameterSpec(iv));
        return new CipherInputStream(inputstream, cipher);
    }
}
