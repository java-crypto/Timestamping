
/*
 * Herkunft/Origin: http://javacrypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.5 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.1
 * Datum/Date (dd.mm.jjjj): 14.04.2020
 * Function: calculates the SHA-256-hash of a large file
 * Beschreibung in / Description in
 * http://javacrypto.bplaced.net/f03-sha-256-und-sha-512-hash-von-einer-datei/
 *
 * Sicherheitshinweis/Security notice
 * Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion,
 * insbesondere mit Blick auf die Sicherheit !
 * Pruefen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
 * The program routines just show the function but please be aware of the security part -
 * check yourself before using in the real world !
 *
 */

import javax.swing.*;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha256LargeFile {

	public static void main(String[] args) throws Exception {

		JTextArea ta = new JTextArea(5, 60);
		ta.setEditable(false);
		String ta_Text = "SHA-256 Hash einer grossen Datei\n";
		System.out.println("SHA-256 Hash einer grossen Datei");


		File file = chooseFile();
		String filename = "";
		try {
			filename =  file.toString();
		} catch (NullPointerException e) {
		}

		if (filename != "") {
			System.out.println("Gewählte Datei: " + filename);
			ta_Text = ta_Text + "Gewählte Datei: " + filename + "\n";
		} else {
			System.out.println("Sie haben keine Datei gewaehlt, das Programm wird beendet.");
			ta_Text = ta_Text + "Sie haben keine Datei gewaehlt, das Programm wird beendet.";
			ta.setText(ta_Text);
			JOptionPane.showMessageDialog(null, new JScrollPane(ta));
			System.exit(0);
		}

		byte[] hashByte = generateSha256Buffered(filename);
		System.out.println("\nSHA-256-Hash der Datei: " + filename);
		ta_Text = ta_Text + "SHA-256-Hash der Datei: " + filename + "\n";
		System.out.println("Data: " + printHexBinary(hashByte));
		ta_Text = ta_Text + "Data: " + printHexBinary(hashByte) + "\n";
		System.out.println("\nSHA-256 Hash einer grossen Datei beendet");
		ta_Text = ta_Text + "SHA-256 Hash einer grossen Datei beendet";
		ta.setText(ta_Text);
		JOptionPane.showMessageDialog(null, new JScrollPane(ta));
	}

    public static byte[] generateSha256Buffered(String filenameString) throws IOException, NoSuchAlgorithmException {
    	byte[] buffer= new byte[8192];
        int count;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(filenameString));
        while ((count = bis.read(buffer)) > 0) {
            md.update(buffer, 0, count);
        }
        bis.close();
        return md.digest();
	}

	public static String printHexBinary(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	private static File chooseFile() {
		JFileChooser chooser = new JFileChooser();
		if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
			return chooser.getSelectedFile();
		} else {
			return null;
		}
	}
}
