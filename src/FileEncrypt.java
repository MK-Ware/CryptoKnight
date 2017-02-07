import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class FileEncrypt
{
	private static byte[] loadFile(String FilePath) throws IOException
	{
		File f = new File(FilePath);
		FileInputStream inData = new FileInputStream(f);
		
		byte[] output = new byte[(int)f.length()];
		inData.read(output);
		inData.close();
		
		return output;
	}
	
	private static void save2File(String FilePath, byte[] data) throws IOException
	{
		File f = new File(FilePath);
		
		FileOutputStream outData = new FileOutputStream(f);
		outData.write(data);
		outData.close();
	}
	
	public static boolean checkFile(String FilePath)
	{
		File check = new File (FilePath);
		return check.exists();
	}
	
	public static void wipeFile(String file2wipe) throws IOException, FileNotFoundException
	{
		File f2w = new File(file2wipe);
		
		long len = f2w.length();
		
		SecureRandom sr = new SecureRandom();
		RandomAccessFile raf = new RandomAccessFile(f2w, "rws");
		raf.seek(0);
		raf.getFilePointer();
		byte[] data = new byte[64];
		int pos = 0;
		while (pos < len)
		{
			sr.nextBytes(data);
			raf.write(data);
			pos += data.length;
		}
		
		raf.close();
		f2w.delete();
	}
	
	public static String CBCEncrypt(int alg, int KeySize, String inFile, String pwd, String mode) throws NoSuchAlgorithmException, InvalidKeySpecException, DataLengthException, IllegalStateException, InvalidCipherTextException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		String res = "";
		
		byte[] plain = loadFile(inFile);
		
		Encryptor enc = new Encryptor();
		enc.setParameters(KeySize, alg);
		enc.setEncParameters(alg, pwd, KeySize, mode);
		byte[] bytesRes = enc.CBCEncrypt(plain, alg);
		
		save2File(inFile + ".enc", bytesRes);
		
		res = "Done! file contents encrypted and saved to a corresponding enc file!"; 
		return res;
	}
	
	public static String CBCDecrypt(int alg, int KeySize, String inFile, String pwd, String mode) throws NoSuchAlgorithmException, InvalidKeySpecException, DataLengthException, IllegalStateException, InvalidCipherTextException, IOException
	{
		String res = "";
		
		if (checkFile(inFile.substring(0, inFile.lastIndexOf("."))))
		{
			res = "A file with the same name already exists! Rename or move it to avoid losing your data!";
			return res;
		}
		
		byte[] Encrypted = loadFile(inFile);
		
		
		Encryptor enc = new Encryptor();
		enc.setParameters(KeySize, alg);
		enc.setDecParameters(Encrypted, alg, pwd, KeySize, mode);
		byte[] bytesRes = enc.CBCDecrypt(Encrypted, alg);
		
		save2File(inFile.substring(0, inFile.lastIndexOf(".")), bytesRes);
		
		res = "Done! file contents decrypted and saved to the specified directory!"; 
		return res;
	}
}