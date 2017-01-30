import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import org.apache.commons.codec.binary.Base64;

public class PwdGen
{
	public static String BoostPass(String OrigPass, int multKey, int RandSeed, int len) throws NoSuchAlgorithmException
	{
		
		String HashedPass = HashFactory.SCryptHash(OrigPass, 13, 128, 256, 50, 0);
		String EncPass = Base64.encodeBase64String(HashedPass.getBytes());
		
		String ExtPass = "";
		
		for (int i = 0; i<=multKey; i++)
		{
			ExtPass += EncPass;
		}
		
		
		StringBuilder sb = new StringBuilder(ExtPass);
				
		Random r = new Random(RandSeed);
		
		int pos1 = r.nextInt(sb.length() - len);
		int pos2 = pos1 + len - 4;
		
		String initPass = sb.substring(pos1, pos2);
		
		StringBuilder sb2 = new StringBuilder(initPass);
		
		String[] symbs = {"*", "#", "@", "!", "$", "_", "-"};
		
		int ins1 = r.nextInt(sb2.length());
		int sym1 = r.nextInt(symbs.length);
		sb2.insert(ins1, symbs[sym1]);
		int ins2 = r.nextInt(sb2.length());
		int sym2 = r.nextInt(symbs.length);
		sb2.insert(ins2, symbs[sym2]);
		int ins3 = r.nextInt(sb2.length());
		int sym3 = r.nextInt(symbs.length);
		sb2.insert(ins3, symbs[sym3]);
		int ins4 = r.nextInt(sb2.length());
		int sym4 = r.nextInt(symbs.length);
		sb2.insert(ins4, symbs[sym4]);
		
		return sb2.toString();
	}
	
	public static String RPassGen(int Chars, int len)
	{
		String CharSpace = null;
		if (Chars == 1)
		{
			CharSpace = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		}
		
		else if (Chars == 2)
		{
			CharSpace = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		}
		
		else if (Chars == 3)
		{
			CharSpace = "abcdefghijklmnopqrstuvwxyz";
		}
		
		else if (Chars == 4)
		{
			CharSpace = "0123456789";
		}
		
		else if (Chars == 5)
		{
			CharSpace = "!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
		}
		
		else if (Chars == 6)
		{
			CharSpace = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		}
		
		else if (Chars == 7)
		{
			CharSpace = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		}
		
		else if (Chars == 8)
		{
			CharSpace = "abcdefghijklmnopqrstuvwxyz0123456789";
		}
		
		else if (Chars == 9)
		{
			CharSpace = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
		}
		
		else if (Chars == 10)
		{
			CharSpace = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
		}
		
		else if (Chars == 11)
		{
			CharSpace = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
		}
		
		else if (Chars == 12)
		{
			CharSpace = "abcdefghijklmnopqrstuvwxyz!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
		}
		
		else if (Chars == 13)
		{
			CharSpace = "0123456789!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
		}
		
		else if (Chars == 14)
		{
			CharSpace = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
		}
		
		else if (Chars == 15)
		{
			CharSpace = "abcdefghijklmnopqrstuvwxyz0123456789!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
		}
		
		StringBuilder sb = new StringBuilder();
		
		for (int i=0; i < len; i++)
		{
			sb.append(CharSpace);
		}
		
		List<String> CharList = String2List(sb.toString());
		
		Collections.shuffle(CharList);
		Collections.shuffle(CharList);
		
		SecureRandom sr = new SecureRandom();
		int pos1 = sr.nextInt(CharList.size() - len);
		int pos2 = pos1 + len;
		
		StringBuilder resSb = List2StringBuilder(CharList);
		
		String resPass = resSb.substring(pos1, pos2);
		
		return resPass;
	}
	
	public static String SpecPassGen(String CharSpace, int len)
	{
		StringBuilder sb = new StringBuilder();
		
		for (int i=0; i < len; i++)
		{
			sb.append(CharSpace);
		}
		
		List<String> CharList = String2List(sb.toString());
		
		Collections.shuffle(CharList);
		Collections.shuffle(CharList);
		
		SecureRandom sr = new SecureRandom();
		int pos1 = sr.nextInt(CharList.size() - len - 1);
		int pos2 = pos1 + len;
		
		StringBuilder resSb = List2StringBuilder(CharList);
		
		String resPass = resSb.substring(pos1, pos2);
		
		return resPass;
	}
	
	private static List<String> String2List(String s)
	{
		List<String> output = new ArrayList<String>();
		for (int i = 0; i < s.length(); i++)
		{
			output.add(s.substring(i, i+1));
		}
		
		return output;
	}
	
	private static StringBuilder List2StringBuilder(List<String> l)
	{
		StringBuilder sb = new StringBuilder();
		
		for (int i = 0; i < l.size(); i++)
		{
			sb.append(l.get(i));
		}
		
		return sb;
	}
}