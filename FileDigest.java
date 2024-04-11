import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class FileDigest {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        if (args.length>1){
            System.out.println("too many arguments");
        } else if (args.length<1) {
            System.out.println("too few arguments");
        }

        HandshakeDigest mydigest = new HandshakeDigest();

        FileInputStream myinstream= new FileInputStream(args[0]);
        FileOutputStream myoutstream = new FileOutputStream("digest.txt");
        byte[] buf= new byte[1];    //seems if reaches the end, the left blank array will make the result wrong... sos just ues [1] to solve

        while(myinstream.read(buf)!=-1){
            mydigest.update(buf);
        }
        byte[] result = mydigest.digest();
        System.out.println(Base64.getEncoder().encodeToString(result));
        myoutstream.write(Base64.getEncoder().encodeToString(result).getBytes());
        myinstream.close();
        myoutstream.close();
    }
}
