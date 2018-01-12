# CryptoKnight
CryptoKnight is a general purpose cryptography app

[![CryptoKnight.v1.0.0_1_1.jpg](https://s23.postimg.org/ii6qx7xsb/Crypto_Knight_v1_0_0_1_1.jpg)](https://postimg.org/image/9aeigiqpz/)

# Features:
1. Text and file encryption
2. 9 encryption algorithms (AES - Rijndael - Twofish - Threefish - Shacal2 - CAST6 - RC6 - Camellia - Serpent)
3. Supports 128, 192, and 256 bit key sizes (512 for Shacal2, and 512 and 1024 for Threefish)
4. Control over block size where possible
5. Option to securely wipe plain file after encryption
6. Supports the following hashing algorithms:
(MD2 - MD5 - SHA1 - SHA224 - SHA256 - SHA384 - SHA512 - bcrypt - scrypt)
7. Password booster generates strong yet reproducible passwords (check the source code or help => FAQ for algorithm details)
8. Random password generator with full control over password characters
9. Secure implementation (uses bouncy castle library) & cryptographic salts
10. User friendly, multi-threaded GUI.
11. Cross platform; works on Windows, mac OSX and Linux.
12. Windows binary version comes with a bundled JRE so you don't even have to have java installed.
13. Open source, 100% free

# Planned features:
1. Steganography (F5 algorithm)

# Setup and Run:
- If you're on Windows, there's a compiled exe binary you can grab from the [releases page](https://github.com/MonroCoury/CryptoKnight/releases). All you need to do is extract the contents of the zip archive (you might need 7-zip, which can be found at: http://www.7-zip.org/download.html), and double click the exe file.. That's it!

- Linux users have one of 2 options (option b should be faster to launch):<br />
a. Run the compiled windows binary same as above using wine.<br />
b. You'll need Java JDK or JRE environment installed ([click here](https://askubuntu.com/questions/48468/how-do-i-install-java) to find out how for ubuntu based distros). Download the jar version from [releases](https://github.com/MonroCoury/CryptoKnight/releases), open your terminal and navigate to the directory containing the .jar file, type "sudo chmod +x CryptoKnight.v1.0.0.jar" (without the quotes, and if you renamed the jar file you should modify the command accordingly). Right click on the jar file and select open with Java Runtime. To create a shortcut on desktop right click on your desktop and select "Create a new launcher here", enter CryptoKnight (or whatever name you want for the launcher) in the name field, type "java -jar (path to the jar file)" (again, without the quotes, eg: java -jar /home/your-username/APPs/CryptoKnight.v1.0.0.jar) in the command field, and finally type "Encrypt your text and files" in the comment field, change the default icon to the left to anything you like (I have included a [default icon.png](https://github.com/MonroCoury/CryptoKnight/raw/master/icon.png) with the source code) and click ok. You're good to go!


#Feedback and contributions are welcome.

# If you like it, don't forget to star the repo
