import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;


/*
 * Skeleton code for class SessionKey
 */

class SessionKey {

    final private SecretKey secretKey;
    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) throws NoSuchAlgorithmException {
        int keylen;
        keylen=length;
        KeyGenerator keyGenerator1= KeyGenerator.getInstance("AES");    //as required, it is aes
        keyGenerator1.init(keylen);
        secretKey=keyGenerator1.generateKey();
    }
    //was planning to use something like biginteger to generate key but cant deal with the secretkey type, keygenerator seems a decent solution here
    //inspired by chatgpt, special thanks for notifying me the presence of this class
    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes)  {
        secretKey= new SecretKeySpec(keybytes,"AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return secretKey.getEncoded();  //just to convert to the bytes
    }
}

