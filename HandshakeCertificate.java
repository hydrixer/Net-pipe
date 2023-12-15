import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.*;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {

    private X509Certificate mycert;
    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {
       mycert =(X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        mycert =(X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certbytes));
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {
        return mycert.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return mycert;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        try {
            mycert.verify(cacert.getCertificate().getPublicKey());
        }catch (Exception e){
            throw e;
        }
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        String[] principle = mycert.getSubjectX500Principal().getName().split(",");
        for(String x: principle){
            x.trim();
            if (x.startsWith("CN=")){
                return x.substring(3);  //if find CN then return
            }
        }
        return null;
    }

    /*
     * return email address of subject
     */
    public String getEmail() throws CertificateParsingException {
        String[] principle = mycert.getSubjectDN().getName().split(",");       //cannot find in principle... so go DN
        for(String x: principle){
            x.trim();
            if (x.startsWith("EMAILADDRESS=")){
                return x.substring("EMAILADDRESS=".length());  //if find email address then return
            }
        }
        return null;
    }
}
