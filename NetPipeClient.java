import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Time;
import java.sql.Timestamp;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert","usercertification");
        arguments.setArgumentSpec("cacert","cacertification");
        arguments.setArgumentSpec("key","clientprivatekey");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) throws IOException, CertificateException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, SignatureException, NoSuchProviderException {
        Socket socket = null;

        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }

        InputStream privatekey_in = new FileInputStream(arguments.get("key"));
        HandshakeCrypto handshakeCryptoprivate = new HandshakeCrypto(privatekey_in.readAllBytes());

        HandshakeCrypto verifycrypto = null;
        HandshakeDigest verifydigest = new HandshakeDigest();

        SessionCipher sessionCipher = new SessionCipher(new SessionKey(128));

        int stage =0;
        //Client hello here
        HandshakeMessage Chello= new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        InputStream usercert_in = new FileInputStream(arguments.get("usercert"));
        HandshakeCertificate usercert= new HandshakeCertificate(usercert_in);
        byte[] usercertBytes = usercert.getBytes();
        String hello_b64 = Base64.getEncoder().encodeToString(usercertBytes);
        Chello.putParameter("Certificate",hello_b64);
        Chello.send(socket);
        stage=1;

        //wait for server hello
        HandshakeCertificate servercert = null;
        if(stage==1) {
            InputStream cacert_in = new FileInputStream(arguments.get("cacert"));
            HandshakeCertificate cacert = new HandshakeCertificate(cacert_in);
            usercert.verify(cacert);
            HandshakeMessage servermsg = HandshakeMessage.recv(socket);
            if (servermsg.getType() == HandshakeMessage.MessageType.SERVERHELLO) {
                byte[] decodedbytes = Base64.getDecoder().decode((String) servermsg.get("Certificate"));
                servercert = new HandshakeCertificate(decodedbytes);
                try {
                    servercert.verify(cacert);
                } catch (Exception e) {
                    System.out.println("serververification failed:" + e);
                    return;
                }
                verifydigest.update(servermsg.getBytes());
                verifycrypto = new HandshakeCrypto(servercert);
                System.out.println("server at port:" + Integer.toString(port) + " verified,CN=" + servercert.getCN());
                stage=2;
            }
        }

        HandshakeMessage Csession = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        //send session
        if (stage==2){
            SessionKey sessionKey = sessionCipher.getSessionKey();
            byte[] sessionkeybytes = sessionKey.getKeyBytes();
            HandshakeCrypto handshakeCrypto = new HandshakeCrypto(servercert);

            String sessoionkeystr= Base64.getEncoder().encodeToString(handshakeCrypto.encrypt(sessionkeybytes));

            byte[] sessionIVbytes = sessionCipher.getIVBytes();
            String sessionIVstr = Base64.getEncoder().encodeToString(handshakeCrypto.encrypt(sessionIVbytes));

            Csession.putParameter("SessionKey",sessoionkeystr);
            Csession.putParameter("SessionIV",sessionIVstr);
            Csession.send(socket);
            stage=3;
            System.out.println("sent key&IV"+ Arrays.toString(sessionKey.getKeyBytes()));
        }

        //send finished
        HandshakeDigest clientdigest = new HandshakeDigest();
        HandshakeMessage Cfinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        if(stage==3){
            clientdigest.update(Chello.getBytes());
            clientdigest.update(Csession.getBytes());
            byte[] clientdigestbytes = handshakeCryptoprivate.encrypt(clientdigest.digest());
            String clientdigeststr = Base64.getEncoder().encodeToString(clientdigestbytes);

            Timestamp clienttimestamp = new Timestamp(System.currentTimeMillis());
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

            byte[] clienttimestampbytes = clienttimestamp.toLocalDateTime().format(formatter).getBytes(StandardCharsets.UTF_8);
            System.out.println(new String(clienttimestampbytes,StandardCharsets.UTF_8));
            String clienttimestampstr = Base64.getEncoder().encodeToString(handshakeCryptoprivate.encrypt(clienttimestampbytes));

            Cfinished.putParameter("Signature",clientdigeststr);;
            Cfinished.putParameter("TimeStamp",clienttimestampstr);
            Cfinished.send(socket);
            System.out.println("sending client finished");

            stage=4;
        }

        //wait for server hello
        if(stage==4){
            HandshakeMessage serverfinished = HandshakeMessage.recv(socket);
            if (serverfinished.getType()!= HandshakeMessage.MessageType.SERVERFINISHED) {
                System.out.println("error! wrong type");
                return;
            }
            else{
                byte[] serverdigestbytes = Base64.getDecoder().decode((String) serverfinished.get("Signature"));

                if (Arrays.equals(verifycrypto.decrypt(serverdigestbytes), verifydigest.digest())){
                    System.out.println("Signature check pass");
                }
                else {
                    System.out.println("Signature check failed");
                    return;
                }

                byte[] servertimestampbytes = Base64.getDecoder().decode((String) serverfinished.get("TimeStamp"));
                String servertimestamp = new String(verifycrypto.decrypt(servertimestampbytes), StandardCharsets.UTF_8);
                Timestamp Stimestamp = Timestamp.valueOf(servertimestamp);
                Timestamp currenttimestamp = new Timestamp(System.currentTimeMillis());
                long oneminutetimebefore = System.currentTimeMillis()-60000;
                Timestamp validtimestamp = new Timestamp(oneminutetimebefore);  //valid period for one minute

                if(Stimestamp.after(validtimestamp)&& Stimestamp.before(currenttimestamp)){
                    System.out.println("Timestamp check pass");
                }
                else {
                    System.out.println("Timestamp check failed");
                    return;
                }
            }
            stage=5;
        }

        System.out.println("HANDSHAKE DONE");

        try {
            Forwarder.forwardStreams(System.in, System.out, sessionCipher.openDecryptedInputStream(socket.getInputStream()),sessionCipher.openEncryptedOutputStream(socket.getOutputStream()), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }
}
