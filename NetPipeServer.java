import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert","servercertification");
        arguments.setArgumentSpec("cacert","cacertification");
        arguments.setArgumentSpec("key","serverprivate");


        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, NoSuchProviderException {
        parseArgs(args);
        ServerSocket serverSocket = null;

        int port = Integer.parseInt(arguments.get("port"));
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
        //get usercert & cacert
        InputStream usercert_in = new FileInputStream(arguments.get("usercert"));
        HandshakeCertificate usercert= new HandshakeCertificate(usercert_in);

        InputStream cacert_in = new FileInputStream(arguments.get("cacert"));
        HandshakeCertificate cacert= new HandshakeCertificate(cacert_in);

        usercert.verify(cacert);

        InputStream privatekey_in = new FileInputStream(arguments.get("key"));
        HandshakeCrypto handshakeCryptoprivate = new HandshakeCrypto(privatekey_in.readAllBytes());

        HandshakeMessage Shello = null;
        HandshakeMessage Sfinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        HandshakeDigest Sdigest = new HandshakeDigest();

        HandshakeDigest verifydigest = new HandshakeDigest();
        HandshakeCrypto verifycrypto = null;

        SessionCipher sessionCipher = null;
        int finished =0;
        boolean cfinished=false;

        //wait Client hello and respond here
        Boolean handshaked = false;
        int stage=0; //this indicates the stage of handshake 0-1-2-3(done)
        while(!handshaked) {
            HandshakeMessage clientmsg = null;
            clientmsg = HandshakeMessage.recv(socket);
            System.out.println("getmessage:"+clientmsg.getType());
            switch (clientmsg.getType()){
                case CLIENTHELLO :{
                    if (stage!=0){
                        return;
                    }
                    byte[] decodedbytes = Base64.getDecoder().decode((String) clientmsg.get("Certificate"));
                    HandshakeCertificate clientcert = new HandshakeCertificate(decodedbytes);
                    try{
                        clientcert.verify(cacert);
                    }catch (Exception e){
                        System.out.println("clientverification failed:"+e);
                        return;
                    }
                    stage++;
                    System.out.println("client at port:"+Integer.toString(port) +" verified,CN="+clientcert.getCN());

                    verifydigest.update(clientmsg.getBytes());
                    verifycrypto = new HandshakeCrypto(clientcert);

                    break;
                }

                case SESSION:{
                    if (stage != 2){
                        return;
                    }
                    byte[] sessionkeybytes = Base64.getDecoder().decode((String) clientmsg.get("SessionKey"));
                    byte[] sessionIVbytes = Base64.getDecoder().decode((String) clientmsg.get("SessionIV"));
                    SessionKey sessionKey = new SessionKey(handshakeCryptoprivate.decrypt(sessionkeybytes));
                    sessionCipher = new SessionCipher(sessionKey, handshakeCryptoprivate.decrypt(sessionIVbytes));
                    stage++;
                    System.out.println("received key&IV"+ Arrays.toString(sessionKey.getKeyBytes()));

                    verifydigest.update(clientmsg.getBytes());

                    break;
                }

                case CLIENTFINISHED:{
                    if (stage != 3 ){
                        System.out.println(stage);
                        return;
                    }

                    byte[] clientdigestbytes = Base64.getDecoder().decode((String) clientmsg.get("Signature"));

                    if (Arrays.equals(verifycrypto.decrypt(clientdigestbytes), verifydigest.digest())){
                        System.out.println("Signature check pass");
                    }
                    else {
                        System.out.println("Signature check failed");
                        return;
                    }

                    byte[] clienttimestampbytes = Base64.getDecoder().decode((String) clientmsg.get("TimeStamp"));
                    String clienttimestamp = new String(verifycrypto.decrypt(clienttimestampbytes), StandardCharsets.UTF_8);
//                    System.out.println("receive client timestamp:"+clienttimestamp);
//                    System.out.println("current time:"+new Timestamp(System.currentTimeMillis()));
                    Timestamp Ctimestamp = Timestamp.valueOf(clienttimestamp);
                    Timestamp currenttimestamp = new Timestamp(System.currentTimeMillis());
                    long oneminutetimebefore = System.currentTimeMillis()-60000;
                    Timestamp validtimestamp = new Timestamp(oneminutetimebefore);  //valid period for one minute

                    if(Ctimestamp.after(validtimestamp)&& Ctimestamp.before(currenttimestamp)){
                        System.out.println("Timestamp check pass");
                    }
                    else {
                        System.out.println("Timestamp check failed");
                        return;
                    }
                    cfinished=true;
                    if(finished==1){
                        handshaked=true;
                    }
                    break;
                }
            }

            if(stage==1){   //Serverhello here
                Shello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
                byte[] usercertBytes = usercert.getBytes();
                String hello_b64 = Base64.getEncoder().encodeToString(usercertBytes);
                Shello.putParameter("Certificate",hello_b64);
                Shello.send(socket);
                System.out.println("Sending server hello");
                stage=2;
            }

            if(stage==3 && finished==0){   //Sfinished
                Sdigest.update(Shello.getBytes());
                byte[] Sdigestbytes = handshakeCryptoprivate.encrypt(Sdigest.digest());
                String Sdigeststr = Base64.getEncoder().encodeToString(Sdigestbytes);

                Timestamp Stimestamp = new Timestamp(System.currentTimeMillis());
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

                byte[] Stimestampbytes = Stimestamp.toLocalDateTime().format(formatter).getBytes(StandardCharsets.UTF_8);
                String Stimestampstr = Base64.getEncoder().encodeToString(handshakeCryptoprivate.encrypt(Stimestampbytes));

                Sfinished.putParameter("Signature",Sdigeststr);
                Sfinished.putParameter("TimeStamp",Stimestampstr);
                Sfinished.send(socket);

                System.out.println("sent server finished");
                finished++;
                if(cfinished){
                    handshaked=true;
                }
            }
        }
        System.out.println("HANDSHAKE DONE");
        try {
            Forwarder.forwardStreams(System.in, System.out, sessionCipher.openDecryptedInputStream(socket.getInputStream()), sessionCipher.openEncryptedOutputStream(socket.getOutputStream()), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}
