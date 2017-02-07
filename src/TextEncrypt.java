import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class TextEncrypt
{
	public enum Algorithm
	{
		AES, Rijndael, Serpent, Camellia, RC6, Twofish, Threefish, CAST6, Shacal2
	};
	
	public static String CBCEncrypt(String plain, String pwd, int KeySize, int alg, String mode) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, DataLengthException, IllegalStateException, InvalidCipherTextException 
	{
		
		String res = "";
		
		Encryptor enc = new Encryptor();
		enc.setParameters(KeySize, alg);
		enc.setEncParameters(alg, pwd, KeySize, mode);
		byte[] bytesRes = enc.CBCEncrypt(plain.getBytes("UTF-8"), alg);
		
		res = new String(Base64.encodeBase64(bytesRes));
		
		return res;
	}
	
	public static String CBCDecrypt(String CText, String pwd, int KeySize, int alg, String mode) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, DataLengthException, IllegalStateException, InvalidCipherTextException
	{		
		String res = "";		
		
		byte[] Encrypted = Base64.decodeBase64(CText.getBytes("UTF-8"));
		
		Encryptor enc = new Encryptor();
		enc.setParameters(KeySize, alg);
		enc.setDecParameters(Encrypted, alg, pwd, KeySize, mode);
		byte[] bytesRes = enc.CBCDecrypt(Encrypted, alg);
		
		res = new String(bytesRes, Charset.forName("UTF-8"));
		return res;
	}
	
}