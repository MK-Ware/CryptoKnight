import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.bouncycastle.crypto.generators.SCrypt;
import org.springframework.security.crypto.keygen.KeyGenerators;

public class HashFactory
{
	
	public static String CommonHash(String p, String alg) throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance(alg);
        
        md.reset();
        
        md.update(p.getBytes(Charset.forName("UTF-8")));
        byte[] resBytes = md.digest();
        String res = new String(Hex.encodeHex(resBytes));
        
        return res;
    }
	
	public static String BCryptHash(String p, int cost) throws NoSuchAlgorithmException
	{
		String salt = KeyGenerators.string().generateKey();
        String res = OpenBSDBCrypt.generate(p.toCharArray(), salt.getBytes(), cost);
        
        return res;
    }
	
	public static String SCryptHash(String p, int cost, int BSize, int par, int len, int s) throws NoSuchAlgorithmException
	{
		String salt = "";
		
		if (s==1)
		{
			salt = KeyGenerators.string().generateKey();
		}
		
		else
		{
			salt = "0621f185e1ba732d";
		}
        byte[] resBytes = SCrypt.generate(p.getBytes(), salt.getBytes(), cost, BSize, par, len);;
        
        String res = new String(Hex.encodeHex(resBytes));
        return res;
    }
}