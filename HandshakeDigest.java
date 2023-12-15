import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {

    /*
     * Constructor -- initialise a digest for SHA-256
     */

    private MessageDigest messageDigest;
    private byte[] digest;
    public HandshakeDigest() throws NoSuchAlgorithmException {
        messageDigest=MessageDigest.getInstance("SHA-256");
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        messageDigest.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
        return messageDigest.digest();
    }
};
