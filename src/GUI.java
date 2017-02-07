import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
import java.io.IOException;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.border.Border;

@SuppressWarnings("serial")
public class GUI extends JFrame{
	JTextArea InputText;
	JTextArea OutputText;
	JComboBox<String> AlgOptions;
	JButton Encrypt;
	JButton Decrypt;
	Thread EncryptThread;
	Thread DecryptThread;
	JComboBox<String> BSOptions;
	Thread MonitorBS;
	JTextField Pwd;
	JCheckBox Hash;
	JButton CopyOut;
	JButton PasteIn;
	Thread CopyThread;
	Thread PasteThread;
	JMenuItem about;
	JMenuItem help;
	JTextField InputFile;
	JTextField OutputDir;
	JButton Browse4F;
	JButton Browse4Dir;
	JButton EncryptF;
	JButton DecryptF;
	Thread OFThread;
	JFileChooser file;
	Thread ODThread;
	JTextArea FReport;
	JComboBox<String> FAlgOptions;
	JComboBox<String> FBSOptions;
	Thread MonitorFBS;
	Thread FEncryptThread;
	Thread FDecryptThread;
	JCheckBox FMode;
	JTextField FPwd;
	JTextArea HInText;
	JTextArea HOutText;
	JComboBox<String> HAlgOptions;
	JSpinner bcCost;
	JSpinner scCost;
	JSpinner scBSize;
	JSpinner scPar;
	JSpinner scLen;
	JButton DoHash;
	JButton HCopyOut;
	JButton HPasteIn;
	Thread HCThread;
	Thread HPThread;
	Thread DHThread;
	JButton HStop;
	JTextArea POut;
	JTextField CPChars;
	JComboBox<String> PChars;
	JSpinner RPassLen;
	JButton RPGen;
	JButton BPGen;
	JTextField OrigPass;
	JSpinner multKey;
	JSpinner RSeed;
	JSpinner BPassLen;
	Thread BPThread;
	Thread RPThread;
	Thread MonitorCPThread;
	JButton CopyPass;
	Thread CopyPassThread;
	JTextArea HelpText;
	JTextArea FAQText;
	JCheckBox wipe;
	
	public void ConstructGUI()
	{
		this.setSize(390,480);

        this.setLocationRelativeTo(null);

        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        this.setTitle("CryptoKnight 0.1");
        
        ListenForButton L4B = new ListenForButton();
        
        JPanel MainPanel = new JPanel();
        
        JTabbedPane Tabs = new JTabbedPane();
        Tabs.setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
        
        JPanel TEPanel = new JPanel();
        TEPanel.setLayout(new GridBagLayout());
        
        GridBagConstraints GBC = new GridBagConstraints(); 
        GBC.gridx = 1;
        GBC.gridy = 1;
        GBC.gridwidth = 1;
        GBC.gridheight = 1;
        GBC.weightx = 0;
        GBC.weighty = 0;
        GBC.insets = new Insets(2, 5, 4, 4);
        GBC.anchor = GridBagConstraints.CENTER;
        GBC.fill = GridBagConstraints.BOTH;
        
        InputText = new JTextArea(10,44);
        InputText.setText("Your input text goes here");
        InputText.setLineWrap(true);
        InputText.setWrapStyleWord(true);
        InputText.selectAll();
        InputText.setFocusable(true);
        GBC.gridx = 1;
        GBC.gridy = 1;
        GBC.gridwidth = 6;
        TEPanel.add(InputText, GBC);
        
        OutputText = new JTextArea(10,44);
        OutputText.setText("The results will appear here. If you're unable to use larger key sizes, refer to the FAQ in the help tab.\n");
        OutputText.setLineWrap(true);
        OutputText.setWrapStyleWord(true);
        OutputText.setFocusable(true);
        OutputText.setEditable(false);
        GBC.gridx = 1;
        GBC.gridy = 2;
        GBC.gridwidth = 6;
        TEPanel.add(OutputText, GBC);
        
        JScrollPane ISP = new JScrollPane(InputText);
        GBC.gridx = 1;
        GBC.gridy = 1;
        TEPanel.add(ISP, GBC);
        
        JScrollPane OSP = new JScrollPane(OutputText);
        GBC.gridx = 1;
        GBC.gridy = 2;
        TEPanel.add(OSP, GBC);
        
        AlgOptions = new JComboBox<String>();
        AlgOptions.addItem("AES");
        AlgOptions.addItem("Rijndael");
        AlgOptions.addItem("Twofish");
        AlgOptions.addItem("Camellia");
        AlgOptions.addItem("Serpent");
        AlgOptions.addItem("CAST6");
        AlgOptions.addItem("RC6");
        AlgOptions.addItem("Threefish");
        AlgOptions.addItem("Shacal2");
        
        GBC.gridx = 2;
        GBC.gridy = 3;
        GBC.fill = GridBagConstraints.WEST;
        GBC.anchor = GridBagConstraints.WEST;
        GBC.gridwidth = 1;
        AlgOptions.addActionListener(L4B);
        TEPanel.add(AlgOptions, GBC);
        
        BSOptions = new JComboBox<String>();
        BSOptions.addItem("128 bit");
        BSOptions.addItem("192 bit");
        BSOptions.addItem("256 bit");
        GBC.gridx = 3;
        GBC.gridy = 3;
        GBC.fill = GridBagConstraints.WEST;
        GBC.anchor = GridBagConstraints.WEST;
        TEPanel.add(BSOptions, GBC);
        
        Hash = new JCheckBox("Quick mode");
        Hash.setToolTipText("Uses SHA256 hashing instead of SHA512. Less Secure!");
        GBC.gridx = 4;
        GBC.gridy = 3;
        TEPanel.add(Hash, GBC);
        
        Pwd = new JTextField("Enter your password", 15);
        GBC.gridx = 1;
        GBC.gridy = 3;
        TEPanel.add(Pwd, GBC);
        
        Encrypt = new JButton("Encrypt");
        GBC.gridx = 5;
        GBC.gridy = 3;
        GBC.anchor = GridBagConstraints.WEST;
        GBC.gridwidth = 1;
        Encrypt.addActionListener(L4B);
        TEPanel.add(Encrypt, GBC);
        
        Decrypt = new JButton("Decrypt");
        GBC.gridx = 6;
        GBC.gridy = 3;
        GBC.anchor = GridBagConstraints.EAST;
        Decrypt.addActionListener(L4B);
        GBC.gridwidth = 1;
        TEPanel.add(Decrypt, GBC);
        
        PasteIn = new JButton("Paste input");
        GBC.gridx = 7;
        GBC.gridy = 1;
        PasteIn.addActionListener(L4B);
        TEPanel.add(PasteIn, GBC);
        
        CopyOut = new JButton("Copy Results");
        GBC.gridx = 7;
        GBC.gridy = 2;
        CopyOut.addActionListener(L4B);
        TEPanel.add(CopyOut, GBC);
        
        JPanel FEPanel = new JPanel();
        FEPanel.setLayout(new BoxLayout(FEPanel, BoxLayout.Y_AXIS));
        
        JPanel inFilePanel = new JPanel();
        
        InputFile = new JTextField("Input file path", 22);
        inFilePanel.add(InputFile);
        
        Browse4F = new JButton("Browse");
        Browse4F.addActionListener(L4B);
        inFilePanel.add(Browse4F);
        
        JPanel outFilePanel = new JPanel();
        
        OutputDir = new JTextField("Output directory path", 22);
        outFilePanel.add(OutputDir);
        
        Browse4Dir = new JButton("Browse");
        Browse4Dir.addActionListener(L4B);
        outFilePanel.add(Browse4Dir);
        
        JPanel AlgPanel = new JPanel();
        
        FPwd = new JTextField("Enter your password", 15);
        AlgPanel.add(FPwd);
        
        FAlgOptions = new JComboBox<String>();
        FAlgOptions.addItem("AES");
        FAlgOptions.addItem("Rijndael");
        FAlgOptions.addItem("Twofish");
        FAlgOptions.addItem("Camellia");
        FAlgOptions.addItem("Serpent");
        FAlgOptions.addItem("CAST6");
        FAlgOptions.addItem("RC6");
        FAlgOptions.addItem("Threefish");
        FAlgOptions.addItem("Shacal2");
        FAlgOptions.addActionListener(L4B);
        AlgPanel.add(FAlgOptions);
        
        FBSOptions = new JComboBox<String>();
        FBSOptions.addItem("128 bit");
        FBSOptions.addItem("192 bit");
        FBSOptions.addItem("256 bit");
        AlgPanel.add(FBSOptions);
        
        FMode = new JCheckBox("Quick Mode");
        FMode.setToolTipText("Uses SHA256 hashing instead of SHA512. Less Secure!");
        AlgPanel.add(FMode);
        
        JPanel FButtons = new JPanel();
        
        wipe = new JCheckBox("Wipe input file");
        wipe.setToolTipText("Check to wipe input file after encryption");
        FButtons.add(wipe);
        
        EncryptF = new JButton("Encrypt");
        EncryptF.addActionListener(L4B);
        FButtons.add(EncryptF);
        
        DecryptF = new JButton("Decrypt");
        DecryptF.addActionListener(L4B);
        FButtons.add(DecryptF);
        
        JPanel ReportPanel = new JPanel();
        
        FReport = new JTextArea(10, 49);
        FReport.setText("If you're unable to use larger key sizes, refer to the FAQ in the help tab.");
        FReport.setEditable(false);
        FReport.setLineWrap(true);
        FReport.setWrapStyleWord(true);
        ReportPanel.add(FReport);
        
        JScrollPane FRSP = new JScrollPane(FReport);
        ReportPanel.add(FRSP);
        
        
        FEPanel.add(inFilePanel);
        FEPanel.add(outFilePanel);
        FEPanel.add(AlgPanel);
        FEPanel.add(FButtons);
        FEPanel.add(ReportPanel);
        
        JPanel HPanel = new JPanel();
        HPanel.setLayout(new BoxLayout(HPanel, BoxLayout.Y_AXIS));
        
        JPanel HInPanel = new JPanel();
        
        HInText = new JTextArea(10, 44);
        HInText.setText("Enter something to hash");
        HInText.setLineWrap(true);
        HInText.setWrapStyleWord(true);
        HInPanel.add(HInText);
        
        JScrollPane HISP = new JScrollPane(HInText);
        HInPanel.add(HISP);
        
        HPasteIn = new JButton("Paste input");
        HPasteIn.addActionListener(L4B);
        HInPanel.add(HPasteIn);
        
        JPanel HOutPanel = new JPanel();
        
        HOutText = new JTextArea(10, 44);
        HOutText.setText("The results will appear here\n");
        HOutText.setLineWrap(true);
        HOutText.setWrapStyleWord(true);
        HOutText.setEditable(false);
        HOutPanel.add(HOutText);
        
        JScrollPane HOSP = new JScrollPane(HOutText);
        HOutPanel.add(HOSP);
        
        HCopyOut = new JButton("Copy output");
        HCopyOut.addActionListener(L4B);
        HOutPanel.add(HCopyOut);
        
        JPanel HParPanel = new JPanel();
        
        HAlgOptions = new JComboBox<String>();
        HAlgOptions.addItem("MD2");
        HAlgOptions.addItem("MD5");
        HAlgOptions.addItem("SHA1");
        HAlgOptions.addItem("SHA-224");
        HAlgOptions.addItem("SHA-256");
        HAlgOptions.addItem("SHA-384");
        HAlgOptions.addItem("SHA-512");
        HAlgOptions.addItem("bcrypt");
        HAlgOptions.addItem("scrypt");
        HAlgOptions.addActionListener(L4B);
        HParPanel.add(HAlgOptions);
        
        SpinnerNumberModel bcm = new SpinnerNumberModel(1, 0, 30, 1);
        bcCost = new JSpinner(bcm);
        bcCost.setToolTipText("bcrypt cost parameter. Between 1 and 30");
        bcCost.setEnabled(false);
        HParPanel.add(bcCost);
        
        SpinnerNumberModel scm = new SpinnerNumberModel(2, 0, 1000, 1);
        scCost = new JSpinner(scm);
        scCost.setToolTipText("scrypt cost parameter. Between 1 and 1000");
        scCost.setEnabled(false);
        HParPanel.add(scCost);
        
        SpinnerNumberModel scbm = new SpinnerNumberModel(1, 0, 1000, 1);
        scBSize = new JSpinner(scbm);
        scBSize.setToolTipText("scrypt block size parameter. >= 1");
        scBSize.setEnabled(false);
        HParPanel.add(scBSize);
        
        SpinnerNumberModel scpm = new SpinnerNumberModel(1, 0, 1000, 1);
        scPar = new JSpinner(scpm);
        scPar.setToolTipText("scrypt parallelization parameter. Between 1 and 1000");
        scPar.setEnabled(false);
        HParPanel.add(scPar);
        
        SpinnerNumberModel sclm = new SpinnerNumberModel(HInText.getText().length(), 0, 1000, 1);
        scLen = new JSpinner(sclm);
        scLen.setToolTipText("scrypt Output length. Preferably >= Input length");
        scLen.setEnabled(false);
        HParPanel.add(scLen);
        
        DoHash = new JButton("Hash");
        DoHash.addActionListener(L4B);
        HParPanel.add(DoHash);
        
        HStop = new JButton("Stop");
        HStop.addActionListener(L4B);
        HParPanel.add(HStop);
                
        HPanel.add(HInPanel);
        HPanel.add(HOutPanel);
        HPanel.add(HParPanel);
        
        JPanel PGPanel = new JPanel();
        PGPanel.setLayout(new BoxLayout(PGPanel, BoxLayout.Y_AXIS));
        
        JPanel BoostPanel = new JPanel();
        Border BoostBorder = BorderFactory.createTitledBorder("Password Booster");
        BoostPanel.setBorder(BoostBorder);
        BoostPanel.setLayout(new BoxLayout(BoostPanel, BoxLayout.Y_AXIS));
        
        JPanel row1 = new JPanel();
        
        OrigPass = new JTextField("Enter your original password", 15);
        row1.add(OrigPass);
        
        SpinnerNumberModel mkm = new SpinnerNumberModel(1, 0, 10000, 1);
        multKey = new JSpinner(mkm);
        multKey.setToolTipText("Multiplication key. Must be memorized!");
        row1.add(multKey);
        
        JPanel row2 = new JPanel();
        
        SpinnerNumberModel rsm = new SpinnerNumberModel(1, 0, 1000000, 1);
        RSeed = new JSpinner(rsm);
        RSeed.setToolTipText("Random Seed. Must be memorized!");
        row2.add(RSeed);
        
        SpinnerNumberModel lm = new SpinnerNumberModel(1, 0, 100, 1);
        BPassLen = new JSpinner(lm);
        BPassLen.setToolTipText("Output password length");
        row2.add(BPassLen);
        
        BPGen = new JButton("Boost");
        BPGen.addActionListener(L4B);
        row2.add(BPGen);
        
        BoostPanel.add(row1);
        BoostPanel.add(row2);
        PGPanel.add(BoostPanel);
        
        JPanel GenPanel = new JPanel();
        Border GenBorder = BorderFactory.createTitledBorder("Random Password Generator");
        GenPanel.setBorder(GenBorder);
        
        PChars = new JComboBox<String>();
        PChars.addItem("Alpha");
        PChars.addItem("Upper case letters");
        PChars.addItem("Lower case letters");
        PChars.addItem("Numbers");
        PChars.addItem("Symbols");
        PChars.addItem("Alphanumeric");
        PChars.addItem("Upper case numeric");
        PChars.addItem("Lower case numeric");
        PChars.addItem("Alphanumeric symbols");
        PChars.addItem("Alpha symbols");
        PChars.addItem("Upper case symbols");
        PChars.addItem("Lower case symbols");
        PChars.addItem("Numeric symbols");
        PChars.addItem("Upper case numeric symbols");
        PChars.addItem("Lower case numeric symbols");
        PChars.addItem("Custom");
        PChars.addActionListener(L4B);
        GenPanel.add(PChars);
        
        CPChars = new JTextField("Specific password characters", 18);
        CPChars.setEnabled(false);
        GenPanel.add(CPChars);
        
        SpinnerNumberModel rplm = new  SpinnerNumberModel(8, 0, 100, 1);
        RPassLen = new JSpinner(rplm);
        RPassLen.setToolTipText("Desired password length");
        GenPanel.add(RPassLen);
        
        RPGen = new JButton("Generate");
        RPGen.addActionListener(L4B);
        GenPanel.add(RPGen);
        
        PGPanel.add(GenPanel);
        
        JPanel PassResPanel = new JPanel();
        
        POut = new JTextArea(10,44);
        POut.setText("Generated password will appear here\n");
        POut.setLineWrap(true);
        POut.setEditable(false);
        PassResPanel.add(POut);
        
        JScrollPane POSP = new JScrollPane(POut);
        PassResPanel.add(POSP);
        
        CopyPass = new JButton("Copy");
        CopyPass.addActionListener(L4B);
        PassResPanel.add(CopyPass);
        
        PGPanel.add(PassResPanel);
        
        JPanel HelpPanel = new JPanel();
        HelpPanel.setLayout(new BoxLayout(HelpPanel, BoxLayout.Y_AXIS));
        
        JPanel HRow1 = new JPanel();
        
        HelpText = new JTextArea(18, 28);
        HelpText.setText("Features:\n\n1. Text and file encryption/decryption\n\n2. Support for the most trusted algorithms:\nAES (128, 192, 256)\nRijndael (128, 192, 256)\nSerpent(128, 192, 256)\nTwofish(128, 192, 256)\nCamellia(128, 192, 256)\nCAST6(128, 192, 256)\nRC6(128, 192, 256)\nShacal2(512)\nThreefish(128, 192, 256, 512, 1024)\n\n3. Supports a wide variety of hashing algorithms:\nmd2\nmd5\nSHA1\nSHA224\nSHA256\nSHA384\nSHA512\nbcrypt\nscrypt\n\n4. Password booster to facilitate generating strong yet reproducible passwords\n\n5. Random password gnerator");
        HelpText.setLineWrap(true);
        HelpText.setWrapStyleWord(true);
        HelpText.setEditable(false);
        HRow1.add(HelpText);
        
        JScrollPane HTSP = new JScrollPane(HelpText);
        HRow1.add(HTSP);
        
        JPanel HRow2 = new JPanel();
        HRow2.setLayout(new BoxLayout(HRow2, BoxLayout.Y_AXIS));
        
        FAQText = new JTextArea(18, 28);
        FAQText.setText("Frequently Asked Questions:\n\nQ: Encryption doesn't work with keys larger than 192 bit! Why?\nA: Due to a ridiculous limitation imposed by Java, you can only use 192 (sometimes 128) bit keys or below. To overcome this, you need to replace the stock security policy files with the unlimited ones provided for free by Oracle. Just google JCE_policy-(your java version number for example 7 or 8).zip, download it, and unzip the content of the included UnlimitedJCEPolicyJDK folder to the directory containing your java security policy files. for example, if you're on windowse, go to the drive where you installed java jre or jdk, and the target directory would be java/jre (or jdk)/lib/security/.\n\nQ: Does this program store my passwords?\nA: No, because it doesn't need to. Before encrypting anything, a key (which is more complicated than just a password) is generated, and the password is part of the key parameters. In other words, the password becomes part of what converts your nice plain text to meaningless gibberish. When you try to decrypt a ciphertext, the decryption password is used to construct key parameters, and if all is good, those parameters convert the nonsense back to readable plain text.\n\nQ: Why doesn't this app provide a password vault?\nA: A password vault is just an encrypted file containing a table of usernames and corresponding passwords. You can easily create a word/excel file, store your passwords in it, and encrypt it using one of the provided algorithms.\n\nQ: Isn't AES and Rijndael one and the same?\nA: No. Rijndael is ablock cipher that supports 128 192 256 bit key size, and 128 192 224 and 256 block sizes. AES is a subset of Rijndael that accepts the same key sizes, but has a fixed block size (128 bit). To offer more flexibility, the app offers both.\n\nQ: Is there a way to recover forgotton passwords?\nA: Unfortunately, there is no way this program can tell who is trying to access the data. As a result there it is impossible to give anyone a chance to recover lost passwords without introducing a backdoor. If you forgot your password, any data encrypted with it is lost forever.\n\nQ: What is 'Quick Mode'?\nA: Normally, the program uses SHA-512 hashing when generating secret keys. By checking Quick Mode you opt to use SHA-256, leading to quicker encryption/decryption. Theoretically, that makes attacks on your keys more affordable, but I still can't imagine a successful attack against them. However, keep in mind that data encrypted with Quick Mode, can only be decrypted with the same mode, and vice versa.\n\nQ: Which encryption algorithm is the most secure?\nA: This question gets asked a lot, short answer: none of the offered algorithms has ever been compromised. Long version: exhausting half the key space of even a 128 bit key os a symmetric cipher would take longer than the life-time of the universe. The most serious threat to your data is a weak password, so choose your password wisely.\n\nQ: What exactly does the password booster do?\nA: This feature is meant to help users generate reproducile, yet powerful passwords. I would've preffered to keep that secret, but since this app is open source, anyone can get the source code and find out themselves. First the password booster calculates an scrypt hash of your password, then it encodes that hashed pass in base64, third step is multiplying the base64 string by a multiplication key provided by the user, afterwards, 2 pseudorandom numbers p1 and p2 are generated based on the random seed (also given by the user) and the specified password length, and used as slice borders for a substring of the huge base64 string from step 3. Finally 4 pseudorandom positions are generated based on the same seed, and 4 special characters are inserted at those positions. The same multiplication key, seed, and length always give the same result with any one password.");
        FAQText.setLineWrap(true);
        FAQText.setWrapStyleWord(true);
        FAQText.setEditable(false);
        HRow1.add(FAQText);
        
        JScrollPane FTSP = new JScrollPane(FAQText);
        HRow1.add(FTSP);
        
        JLabel MyLabel = new JLabel("CryptoKnight Cryptography app");
        HRow2.add(MyLabel);
        
        JLabel MyLabel2 = new JLabel("           By Monro Coury");
        HRow2.add(MyLabel2);
        
        HelpPanel.add(HRow1);
        HelpPanel.add(HRow2);
        
        Tabs.addTab("Text Encryptor", TEPanel);
        Tabs.addTab("File Encryptor", FEPanel);
        Tabs.addTab("Hash Factory", HPanel);
        Tabs.addTab("Password Generator", PGPanel);
        Tabs.addTab("Help", HelpPanel);
        MainPanel.add(Tabs);
        
        JMenuBar bar = new JMenuBar();
        JMenu aboutM = new JMenu("About");
        
        help = new JMenuItem("Help");
        help.addActionListener(L4B);
        aboutM.add(help);
        
        about = new JMenuItem("About");
        about.addActionListener(L4B);
        aboutM.add(about);
        
        bar.add(aboutM);
        
        this.add(MainPanel);
        this.setJMenuBar(bar);
        this.pack();
        this.setVisible(true);
	}
	
	private class ListenForButton implements ActionListener
    {
        public void actionPerformed (ActionEvent e)
        {
        	if (e.getSource() == Encrypt)
        	{
        		EncryptThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				long start = System.nanoTime();
        				OutputText.setText("Encrypting");
        				String CT = "";
        				try
        				{
        					if (Hash.isSelected())
        					{
        						CT = TextEncrypt.CBCEncrypt(InputText.getText(), Pwd.getText(), Integer.parseInt(BSOptions.getSelectedItem().toString().substring(0, BSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), AlgOptions.getSelectedIndex(), "Q");
        					}
        					
        					else
        					{
        						CT = TextEncrypt.CBCEncrypt(InputText.getText(), Pwd.getText(), Integer.parseInt(BSOptions.getSelectedItem().toString().substring(0, BSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), AlgOptions.getSelectedIndex(), "S");
        					}
        				}
        				
        				catch (Exception e)
        				{
        					CT = e.getMessage();
        				}
        				long elapsed = System.nanoTime() - start;
        				
        				OutputText.setText(CT + "\n\nTotal time: " + elapsed/1e9 + " seconds.");
        				
        			}//end of run body
        			
        		};//end of thread body
        		EncryptThread.start();
        		
        	}//end of if
        	
        	else if (e.getSource() == Decrypt)
        	{
        		DecryptThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				long start = System.nanoTime();
        				OutputText.setText("Decrypting");
        				String CT = "";
        				try
        				{
        					if (Hash.isSelected())
        					{
        						CT = TextEncrypt.CBCDecrypt(InputText.getText(), Pwd.getText(), Integer.parseInt(BSOptions.getSelectedItem().toString().substring(0, BSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), AlgOptions.getSelectedIndex(), "Q");
        					}
        					
        					else
        					{
        						CT = TextEncrypt.CBCDecrypt(InputText.getText(), Pwd.getText(), Integer.parseInt(BSOptions.getSelectedItem().toString().substring(0, BSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), AlgOptions.getSelectedIndex(), "S");
        					}
        				}
        				
        				catch (Exception e)
        				{
        					CT = e.getMessage();
        				}
        				long elapsed = System.nanoTime() - start;
        				
        				OutputText.setText(CT + "\n\nTotal time: " + elapsed/1e9 + " seconds.");
        				
        			}//end of run body
        			
        		};//end of thread body
        		DecryptThread.start();
        	}//end of else if
        	
        	else if (e.getSource() == AlgOptions)
        	{
        		MonitorBS = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				if (AlgOptions.getSelectedItem().toString().equalsIgnoreCase("Threefish"))
                		{
        					BSOptions.removeAllItems();
        					BSOptions.addItem("256 bit");
        					BSOptions.addItem("512 bit");
                			BSOptions.addItem("1024 bit");
                		}
                		
        				if ((!AlgOptions.getSelectedItem().toString().equalsIgnoreCase("Threefish")) && (AlgOptions.getItemCount() >= 4))
                		{
                			BSOptions.removeAllItems();
                			BSOptions.addItem("128 bit");
                	        BSOptions.addItem("192 bit");
                	        BSOptions.addItem("256 bit");
                		}
        				
        				if ((AlgOptions.getSelectedItem().toString().equalsIgnoreCase("Shacal2")))
                		{
                			BSOptions.removeAllItems();
                			BSOptions.addItem("512 bit");
                		}
        			}
        			
        		};
        		MonitorBS.start();
        	}
        	
        	else if (e.getSource() == CopyOut)
        	{
        		CopyThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				StringSelection selection = null;
        				
        				if (!OutputText.getText().equalsIgnoreCase("The results will appear here. If you're unable to use larger key sizes, refer to the FAQ in the help tab.\n"))
        				{
        					selection = new StringSelection(OutputText.getText().substring(0, OutputText.getText().length() - 34));
        				}
        				
        				else
        				{
        					selection = new StringSelection(OutputText.getText().substring(0, OutputText.getText().length() - 1));
        				}
        				
        				Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        				cb.setContents(selection, selection);
        			}
        		};
        		
        		CopyThread.start();
        	}
        	
        	else if (e.getSource() == PasteIn)
        	{
        		PasteThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        				Transferable contents = cb.getContents(null);
        				try {
							String input = (String) contents.getTransferData(DataFlavor.stringFlavor);
							InputText.setText(input);
						} catch (UnsupportedFlavorException e) {
							InputText.setText(e.toString());
						} catch (IOException e) {
							InputText.setText(e.toString());
						}
        			}
        		};
        		
        		PasteThread.start();
        	}
        	
        	else if (e.getSource() == Browse4F)
        	{
        		OFThread = new Thread(){
                    @Override
                    public void run(){
                        file = new JFileChooser();
				
                        int returnValue = file.showOpenDialog(null);

                        if (returnValue == JFileChooser.APPROVE_OPTION)
                        {
                            String fname = file.getSelectedFile().getAbsolutePath();

                            InputFile.setText(fname);
                        }
                        
                    }
                };
                OFThread.start();
        	}
        	
        	else if (e.getSource() == Browse4Dir)
        	{
        		ODThread = new Thread(){
                    @Override
                    public void run(){
                        file = new JFileChooser();

                        file.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

                        int returnValue = file.showOpenDialog(null);

                        if (returnValue == JFileChooser.APPROVE_OPTION)
                        {
                            String dirname = file.getSelectedFile().getAbsolutePath();

                            OutputDir.setText(dirname);
                        }
                        
                    }
                };
                ODThread.start();
        	}
        	
        	else if (e.getSource() == FAlgOptions)
        	{
        		MonitorFBS = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				if (FAlgOptions.getSelectedItem().toString().equalsIgnoreCase("Threefish"))
                		{
        					FBSOptions.addItem("512 bit");
                			FBSOptions.addItem("1024 bit");
                		}
                		
        				if ((!FAlgOptions.getSelectedItem().toString().equalsIgnoreCase("Threefish")) && (FAlgOptions.getItemCount() >= 4))
                		{
                			FBSOptions.removeAllItems();
                			FBSOptions.addItem("128 bit");
                	        FBSOptions.addItem("192 bit");
                	        FBSOptions.addItem("256 bit");
                		}
        				
        				if ((FAlgOptions.getSelectedItem().toString().equalsIgnoreCase("Shacal2")))
                		{
                			FBSOptions.removeAllItems();
                			FBSOptions.addItem("512 bit");
                		}
        			}
        			
        		};
        		MonitorFBS.start();
        	}
        	
        	else if (e.getSource() == EncryptF)
        	{
        		FEncryptThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				FReport.setText("Encrypting...");
        				long start = System.nanoTime();
        				String OpRes = "";
        				if (wipe.isSelected())
        				{
        					if (FileEncrypt.checkFile(InputFile.getText() + ".enc"))
        					{
        						JOptionPane.showMessageDialog(GUI.this, "An encrypted file with the same name already exists!\nRename or move it to avoid losing your data!", "Warning!", JOptionPane.WARNING_MESSAGE);
        					}
        					
        					else
        					{
        						try 
            					{
        							try
        	        				{
        	        					if (FMode.isSelected())
        	        					{
        	        						OpRes = FileEncrypt.CBCEncrypt(FAlgOptions.getSelectedIndex(), Integer.parseInt(FBSOptions.getSelectedItem().toString().substring(0, FBSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), InputFile.getText(), FPwd.getText(), "Q");
        	        					}
        	        					
        	        					else
        	        					{
        	        						OpRes= FileEncrypt.CBCEncrypt(FAlgOptions.getSelectedIndex(), Integer.parseInt(FBSOptions.getSelectedItem().toString().substring(0, FBSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), InputFile.getText(), FPwd.getText(), "S");
        	        					}
        	        				}
        	        				
        	        				catch (Exception e)
        	        				{
        	        					OpRes = e.getMessage();
        	        				}
        							
            						FileEncrypt.wipeFile(InputFile.getText());
            						JOptionPane.showMessageDialog(GUI.this, "Input file wiped successfully", "Success!", JOptionPane.INFORMATION_MESSAGE);
    							}
            					catch (FileNotFoundException e)
            					{
            						JOptionPane.showMessageDialog(GUI.this, "Could not find the input file", "Error", JOptionPane.ERROR_MESSAGE);
    							}
            					catch (IOException e)
            					{
            						JOptionPane.showMessageDialog(GUI.this, "Could not find or access the input file", "Error", JOptionPane.ERROR_MESSAGE);
    							}
        					}
        					
        				}
        				
        				else
        				{
        					try
            				{
            					if (FMode.isSelected())
            					{
            						OpRes = FileEncrypt.CBCEncrypt(FAlgOptions.getSelectedIndex(), Integer.parseInt(FBSOptions.getSelectedItem().toString().substring(0, FBSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), InputFile.getText(), FPwd.getText(), "Q");
            					}
            					
            					else
            					{
            						OpRes= FileEncrypt.CBCEncrypt(FAlgOptions.getSelectedIndex(), Integer.parseInt(FBSOptions.getSelectedItem().toString().substring(0, FBSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), InputFile.getText(), FPwd.getText(), "S");
            					}
            				}
            				
            				catch (Exception e)
            				{
            					OpRes = e.getMessage();
            				}
        				}
        				
        				long elapsed = System.nanoTime() - start;
        				
        				FReport.setText(OpRes + "\n\nTotal time: " + elapsed/1e9 + " seconds.");

        				

        			}//end of run body
        			
        		};//end of thread body
        		FEncryptThread.start();
        	}
        	
        	else if (e.getSource() == DecryptF)
        	{
        		FDecryptThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				FReport.setText("Decrypting...");
        				long start = System.nanoTime();
        				String OpRes = "";
        				if (wipe.isSelected())
        				{
        					if (FileEncrypt.checkFile(InputFile.getText() + ".enc"))
        					{
        						JOptionPane.showMessageDialog(GUI.this, "An encrypted file with the same name already exists!\nRename or move it to avoid losing your data!", "Warning!", JOptionPane.WARNING_MESSAGE);
        					}
        					
        					else
        					{
        						try 
            					{
        							try
        	        				{
        	        					if (FMode.isSelected())
        	        					{
        	        						OpRes = FileEncrypt.CBCDecrypt(FAlgOptions.getSelectedIndex(), Integer.parseInt(FBSOptions.getSelectedItem().toString().substring(0, FBSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), InputFile.getText(), FPwd.getText(), "Q");
        	        					}
        	        					
        	        					else
        	        					{
        	        						OpRes= FileEncrypt.CBCDecrypt(FAlgOptions.getSelectedIndex(), Integer.parseInt(FBSOptions.getSelectedItem().toString().substring(0, FBSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), InputFile.getText(), FPwd.getText(), "S");
        	        					}
        	        				}
        	        				
        	        				catch (Exception e)
        	        				{
        	        					OpRes = e.getMessage();
        	        				}
        							
            						FileEncrypt.wipeFile(InputFile.getText());
            						JOptionPane.showMessageDialog(GUI.this, "Input file wiped successfully", "Success!", JOptionPane.INFORMATION_MESSAGE);
    							}
            					catch (FileNotFoundException e)
            					{
            						JOptionPane.showMessageDialog(GUI.this, "Could not find the input file", "Error", JOptionPane.ERROR_MESSAGE);
    							}
            					catch (IOException e)
            					{
            						JOptionPane.showMessageDialog(GUI.this, "Could not find or access the input file", "Error", JOptionPane.ERROR_MESSAGE);
    							}
        					}
        					
        				}
        				
        				else
        				{
        					try
            				{
            					if (FMode.isSelected())
            					{
            						OpRes = FileEncrypt.CBCDecrypt(FAlgOptions.getSelectedIndex(), Integer.parseInt(FBSOptions.getSelectedItem().toString().substring(0, FBSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), InputFile.getText(), FPwd.getText(), "Q");
            					}
            					
            					else
            					{
            						OpRes= FileEncrypt.CBCDecrypt(FAlgOptions.getSelectedIndex(), Integer.parseInt(FBSOptions.getSelectedItem().toString().substring(0, FBSOptions.getSelectedItem().toString().lastIndexOf("b") - 1)), InputFile.getText(), FPwd.getText(), "S");
            					}
            				}
            				
            				catch (Exception e)
            				{
            					OpRes = e.getMessage();
            				}
        				}
        				long elapsed = System.nanoTime() - start;
        				
        				FReport.setText(OpRes + "\n\nTotal time: " + elapsed/1e9 + " seconds.");
        				
        			}//end of run body
        			
        		};//end of thread body
        		FDecryptThread.start();
        	}
        	
        	else if (e.getSource() == HAlgOptions)
        	{
        		if (HAlgOptions.getSelectedItem().toString().equalsIgnoreCase("bcrypt"))
        		{
        			bcCost.setEnabled(true);
        		}
        		
        		if (HAlgOptions.getSelectedItem().toString().equalsIgnoreCase("scrypt"))
        		{
        			scCost.setEnabled(true);
        			scBSize.setEnabled(true);
        			scPar.setEnabled(true);
        			scLen.setEnabled(true);
        		}
        		
        		if (!HAlgOptions.getSelectedItem().toString().equalsIgnoreCase("bcrypt"))
        		{
        			bcCost.setEnabled(false);
        		}
        		
        		if (!HAlgOptions.getSelectedItem().toString().equalsIgnoreCase("scrypt"))
        		{
        			scCost.setEnabled(false);
        			scBSize.setEnabled(false);
        			scPar.setEnabled(false);
        			scLen.setEnabled(false);
        		}
        	}
        	
        	else if (e.getSource() == HPasteIn)
        	{
        		HPThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        				Transferable contents = cb.getContents(null);
        				try {
							String input = (String) contents.getTransferData(DataFlavor.stringFlavor);
							HInText.setText(input);
						} catch (UnsupportedFlavorException e) {
							HInText.setText(e.toString());
						} catch (IOException e) {
							HInText.setText(e.toString());
						}
        			}
        		};
        		HPThread.start();
        	}
        	
        	else if (e.getSource() == HCopyOut)
        	{
        		HCThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				StringSelection selection = new StringSelection(HOutText.getText().substring(0, HOutText.getText().indexOf("\n")));
        				Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        				cb.setContents(selection, selection);
        			}
        		};
        		HCThread.start();
        	}
        	
        	else if (e.getSource() == DoHash)
        	{
        		DHThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				HOutText.setText("Hashing...");
        				long start = System.nanoTime();
        				String HRes = "";
        				String p = HInText.getText();
        				try
        				{
        					switch (HAlgOptions.getSelectedIndex())
        					{
        					case 7:
        						HRes = HashFactory.BCryptHash(p, (Integer) bcCost.getValue());
        						break;
        					case 8:
        						HRes = HashFactory.SCryptHash(p, (Integer) scCost.getValue(), (Integer) scBSize.getValue(), (Integer) scPar.getValue(), (Integer) scLen.getValue(), 1);
        						break;
        					default:
        						HRes = HashFactory.CommonHash(p, HAlgOptions.getSelectedItem().toString());
        						break;
        						
        					}
        					
        				}
        				catch (Exception e)
        				{
        					HRes = e.getMessage();
        				}
        				long elapsed = System.nanoTime() - start;
        				HOutText.setText(HRes + "\n\nTotal time: " + elapsed/1e9 + " seconds.");;
        			}
        		};
        		DHThread.start();
        		
        	}
        	
        	else if (e.getSource() == HStop && DHThread.isAlive())
        	{
        		DHThread.interrupt();
        		HOutText.setText("Operation interrupted by user");
        	}
        	
        	else if (e.getSource() == BPGen)
        	{
        		BPThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				if ((Integer) BPassLen.getValue() < 8)
        				{
        					JOptionPane.showMessageDialog(GUI.this, "Passwords that are below 8 characters in length are weak!", "Warning!", JOptionPane.WARNING_MESSAGE);
        				}
        				
        				else
        				{
        					long start = System.nanoTime();
            				POut.setText("Boosting...");
            				String newPass ="";
            				try
            				{
                				newPass = PwdGen.BoostPass(OrigPass.getText(), (Integer) multKey.getValue(), (Integer) RSeed.getValue(), (Integer) BPassLen.getValue());
            				}
            				catch (Exception e)
            				{
            					newPass = "Unappropriate hashing algorithm";
            				}
            				long elapsed = System.nanoTime() - start;
            				POut.setText(newPass + "\n\nTotal time: " + elapsed/1e9 + " seconds.");
        				}
        				
        			}
        		};
        		BPThread.start();
        	}
        	
        	else if (e.getSource() == RPGen)
        	{
            	RPThread = new Thread()
            	{
            		@Override
                    public void run()
        			{
            			if ((Integer) RPassLen.getValue() < 8)
        				{
        					JOptionPane.showMessageDialog(GUI.this, "Passwords that are below 8 characters in length are weak!", "Warning!", JOptionPane.WARNING_MESSAGE);
        				}
            			
            			else
            			{
            				long start = System.nanoTime();
            				String newPass ="";
            				try
            				{
            					if (PChars.getSelectedItem().toString().equalsIgnoreCase("custom"))
            					{
            						newPass = PwdGen.SpecPassGen(CPChars.getText(), (Integer) RPassLen.getValue());
            					}
            					
            					else
            					{
            						newPass = PwdGen.RPassGen(PChars.getSelectedIndex() + 1, (Integer) RPassLen.getValue());
            					}
                				
            				}
            				catch (Exception e)
            				{
            					newPass = "Unappropriate hashing algorithm";
            				}
            				long elapsed = System.nanoTime() - start;
            				POut.setText(newPass + "\n\nTotal time: " + elapsed/1e9 + " seconds.");
            			}
            			
        			}
            	};
            	RPThread.start();
        	}
        	
        	else if (e.getSource() == PChars)
        	{
        		MonitorCPThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				if (PChars.getSelectedItem().toString().equalsIgnoreCase("custom"))
        				{
        					CPChars.setEnabled(true);
        				}
        				
        				else
        				{
        					CPChars.setEnabled(false);
        				}
        			}
        		};
        		MonitorCPThread.start();
        	}
        	
        	else if (e.getSource() == CopyPass)
        	{
        		CopyPassThread = new Thread()
        		{
        			@Override
                    public void run()
        			{
        				StringSelection selection = new StringSelection(POut.getText().substring(0, POut.getText().indexOf("\n")));
        				Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        				cb.setContents(selection, selection);
        			}
        		};
        		
        		CopyPassThread.start();
        	}
        	
        	else if (e.getSource() == help)
            {
               JOptionPane.showMessageDialog(GUI.this, "CryptoKnight is a general purpose cryptography app.\n\n Hover your mouse over untitled entry components for hints.", "Help", JOptionPane.QUESTION_MESSAGE);
            }
        	
        	else if (e.getSource() == about)
            {
               JOptionPane.showMessageDialog(GUI.this, "License:\n\nCopyright (C) 2017 MCoury\nThis program is free software: you can redistribute it and/or modify\nit under the terms of the GNU General Public License as published by\nthe Free Software Foundation, either version 3 of the License, or\nany later version.\nThis program is distributed in the hope that it will be useful,\nbut WITHOUT ANY WARRANTY; without even the implied warranty of\nMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\nGNU General Public License for more details.\nYou should have received a copy of the GNU General Public License\nalong with this program.  If not, see http://www.gnu.org/licenses .\n\nWritten in Java\nBy MCoury", "About", JOptionPane.INFORMATION_MESSAGE);
            }
        	
        }//end of actionperformed
        
     }//end of LFB class
	
}