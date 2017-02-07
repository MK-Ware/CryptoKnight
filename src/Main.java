/*
 * Copyright (C) 2017 MCoury
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.UIManager;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import com.pagosoft.plaf.PgsLookAndFeel;

@SuppressWarnings({"unused" })
public class Main
{

	public static void main(String[] args) throws InvalidKeyException, DataLengthException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, IllegalStateException, InvalidCipherTextException
	{

		try 
		{
			UIManager.setLookAndFeel("com.pagosoft.plaf.PgsLookAndFeel");
		}

		catch (Exception e)
		{
			;
		}
		GUI MainGUI = new GUI();
		MainGUI.ConstructGUI();
		
//		String CT = TextEncrypt.CBCDecrypt("8mjf2sqScPChi5lJQut6U5phB6IW8ze90WdqDm+ulLU1NWI2ODZlYzVmMjYxYTA5", "secret", 256, 0, "Q");
//		
//		System.out.println(CT);

	}

}
