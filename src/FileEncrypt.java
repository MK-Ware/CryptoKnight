import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.engines.Shacal2Engine;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;
import org.springframework.security.crypto.keygen.KeyGenerators;

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
	
	public static String CBCEncrypt(String alg, int KeySize, String inFile, String pwd, String mode) throws NoSuchAlgorithmException, InvalidKeySpecException, DataLengthException, IllegalStateException, InvalidCipherTextException, IOException
	{
		String res = "";
		
		if (checkFile(inFile + ".enc"))
		{
			res = "An encrypted file with the same name already exists! Rename or move it to avoid losing your data!";
			return res;
		}
		String[] algs = {"AES", "RIJNDAEL", "SERPENT", "CAMELLIA", "RC6", "TWOFISH", "THREEFISH", "CAST6", "SHACAL2"};
		List<String> algsList = Arrays.asList(algs);
		
		int blockSize =0;
		
		if (!algsList.contains(alg.toUpperCase()))
		{
			res = "Unsupported Algorithm";
			return res;
		}
		
		if (alg.equalsIgnoreCase("Threefish") || alg.equalsIgnoreCase("Rijndael"))
		{
			blockSize = KeySize;
		}
		else if (alg.equalsIgnoreCase("Shacal2"))
		{
			blockSize = 256;
		}
		
		else
		{
			blockSize = 128;
		}
		
		byte[] plain = loadFile(inFile);
		
		byte[] ivData = new byte[blockSize/8];
		SecureRandom r = new SecureRandom();
		r.nextBytes(ivData);
		
		BlockCipherPadding padding = new PKCS7Padding();
		SecretKeyFactory factory = null;
		if (mode.equalsIgnoreCase("Q"))
		{
			factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		}
		
		else
		{
			factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		}
		String salt = KeyGenerators.string().generateKey();
		KeySpec spec = new PBEKeySpec (pwd.toCharArray(), salt.getBytes(), 65536, KeySize);
		SecretKey tmp = factory.generateSecret(spec);
		KeyParameter keyParam = new KeyParameter(tmp.getEncoded());
		CipherParameters cipherParams = null;
		BufferedBlockCipher cipher = null;
		
		if (alg.equalsIgnoreCase("AES"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("Serpent"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SerpentEngine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("Camellia"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new CamelliaEngine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("Twofish"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("CAST6"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new CAST6Engine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("RC6"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new RC6Engine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("Threefish"))
		{
			TweakableBlockCipherParameters tKeyParams = new TweakableBlockCipherParameters(keyParam, salt.getBytes());
			cipherParams = new ParametersWithIV(tKeyParams, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new ThreefishEngine(KeySize)), padding);
		}
		
		else if (alg.equalsIgnoreCase("Rijndael"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new RijndaelEngine(KeySize)), padding);
		}
		
		else if (alg.equalsIgnoreCase("Shacal2"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new Shacal2Engine()), padding);
		}
		
		cipher.reset();
		cipher.init(true, cipherParams);
		
		byte[] output = new byte[cipher.getOutputSize(plain.length)];
		int bytesWrittenOut = cipher.processBytes(plain, 0, plain.length, output, 0);
		bytesWrittenOut += cipher.doFinal(output, bytesWrittenOut);
		
		byte[] bytesAll = new byte[ivData.length + output.length + salt.getBytes().length];
		System.arraycopy(ivData, 0, bytesAll, 0, ivData.length);
		System.arraycopy(output, 0, bytesAll, ivData.length, output.length);
		System.arraycopy(salt.getBytes(), 0, bytesAll, ivData.length + output.length, salt.getBytes().length);
		
		save2File(inFile + ".enc", bytesAll);
		
		res = "Done! file contents encrypted and saved to a corresponding enc file!"; 
		return res;
	}
	
	public static String CBCDecrypt(String alg, int KeySize, String inFile, String pwd, String mode) throws NoSuchAlgorithmException, InvalidKeySpecException, DataLengthException, IllegalStateException, InvalidCipherTextException, IOException
	{
		String res = "";
		
		if (checkFile(inFile.substring(0, inFile.lastIndexOf("."))))
		{
			res = "A file with the same name already exists! Rename or move it to avoid losing your data!";
			return res;
		}
		String[] algs = {"AES", "RIJNDAEL", "SERPENT", "CAMELLIA", "RC6", "TWOFISH", "THREEFISH", "CAST6", "SHACAL2"};
		List<String> algsList = Arrays.asList(algs);

		int blockSize =0;
		
		if (!algsList.contains(alg.toUpperCase()))
		{
			res = "Unsupported Algorithm";
			return res;
		}
		
		if (alg.equalsIgnoreCase("Threefish") || alg.equalsIgnoreCase("Rijndael"))
		{
			blockSize = KeySize;
		}
		else if (alg.equalsIgnoreCase("Shacal2"))
		{
			blockSize = 256;
		}
		
		else
		{
			blockSize = 128;
		}
		
		byte[] Encrypted = loadFile(inFile);
		
		byte[] ivData = new byte[blockSize/8];
		System.arraycopy(Encrypted, 0, ivData, 0, blockSize/8);
		
		byte[] salt = new byte[16];
		System.arraycopy(Encrypted, Encrypted.length - 16 , salt, 0, 16);
		
		byte[] rawEnc = new byte[Encrypted.length - 16];
		System.arraycopy(Encrypted, 0 , rawEnc, 0, Encrypted.length - 16);
		
		BlockCipherPadding padding = new PKCS7Padding();
		SecretKeyFactory factory = null;
		
		if (mode.equalsIgnoreCase("Q"))
		{
			factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		}
		
		else
		{
			factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		}
		
		KeySpec spec = new PBEKeySpec (pwd.toCharArray(), salt, 65536, KeySize);
		SecretKey tmp = factory.generateSecret(spec);
		KeyParameter keyParam = new KeyParameter(tmp.getEncoded());
		CipherParameters cipherParams = null;
		BufferedBlockCipher cipher = null;
		
		if (alg.equalsIgnoreCase("AES"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("Serpent"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SerpentEngine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("Camellia"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new CamelliaEngine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("Twofish"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("CAST6"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new CAST6Engine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("RC6"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new RC6Engine()), padding);
		}
		
		else if (alg.equalsIgnoreCase("Threefish"))
		{
			TweakableBlockCipherParameters tKeyParams = new TweakableBlockCipherParameters(keyParam, salt);
			cipherParams = new ParametersWithIV(tKeyParams, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new ThreefishEngine(KeySize)), padding);
		}
		
		else if (alg.equalsIgnoreCase("Rijndael"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new RijndaelEngine(KeySize)), padding);
		}
		
		else if (alg.equalsIgnoreCase("Shacal2"))
		{
			cipherParams = new ParametersWithIV(keyParam, ivData);
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new Shacal2Engine()), padding);
		}
		
		cipher.reset();
		cipher.init(false, cipherParams);
		
		byte[] output = new byte[cipher.getOutputSize(rawEnc.length - blockSize/8)];
		int bytesWrittenin = cipher.processBytes(rawEnc, blockSize/8, rawEnc.length - blockSize/8, output, 0);
		bytesWrittenin += cipher.doFinal(output, bytesWrittenin);
		
		byte[] Dec = new byte[bytesWrittenin];
		System.arraycopy(output, 0, Dec, 0, bytesWrittenin);
		
		save2File(inFile.substring(0, inFile.lastIndexOf(".")), Dec);
		
		res = "Done! file contents decrypted and saved to the specified directory!"; 
		return res;
	}
}