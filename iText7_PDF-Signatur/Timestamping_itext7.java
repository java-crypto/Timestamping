
/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Basis Programmierer/Basic Programmer: Bruno Lowagie
 * This class is part of the white paper entitled "Digital Signatures for PDF documents"
 * For more info, go to: http://itextpdf.com/learn
 * Lizenz/License: GNU Affero General Public License Version 3
 * Lizenttext/Licence: <https://www.gnu.org/licenses/agpl-3.0.de.html>
 * getestet mit/tested with: Java Runtime Environment 11.0.5 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.1
 * Datum/Date (dd.mm.jjjj): 21.04.2020
 * Funktion: signiert ein PDF Dokument und fuegt einen Zeitstempel hinzu
 * Function: signs a PDF document and adds a timestamp
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/
 *
 * Sicherheitshinweis/Security notice
 * Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion,
 * insbesondere mit Blick auf die Sicherheit !
 * Pruefen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
 * The program routines just show the function but please be aware of the security part -
 * check yourself before using in the real world !
 *
 * Sie benoetigen mehrere Bibliotheken / you need several libraries:
 * iText7 Community Version: https://github.com/itext/itext7/releases/tag/7.1.11
 * Bouncy Castle:
 * bcprov-jdk15on-1.65.jar https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on/1.65
 * bcpkix-jdk15on-1.65.jar https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15on/1.65
 * Logger:
 * slf4j-api-1.7.30.jar https://mvnrepository.com/artifact/org.slf4j/slf4j-api/1.7.30
 * slf4j-simple-1.7.30.jar https://mvnrepository.com/artifact/org.slf4j/slf4j-simple/1.7.30
 *
 * Alle Bibliotheken sind auch in meinem GitHub-Archiv zu finden: /
 * All libraries are available under my GitHub-Repository:
 * https://github.com/java-crypto/Timestamping/tree/master/iText7_PDF-Signatur
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Collection;

public class Timestamping_itext7 {

    private static Logger LOGGER = LoggerFactory.getLogger(Timestamping_itext7.class);
    public static Provider provider = new BouncyCastleProvider();

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        // bouncy castle aufnehmen
        if (Security.getProvider("BC") == null) {
            Security.addProvider(provider);
        }

        // setup daten start
        String orgFilename = "java-crypto_bplaced_net.pdf";
        String timestampedFilename = "java-crypto_bplaced_net_itext7_ts.pdf";
        String timestampedFilenamePath = "";
        String timestampReason = "Test fuer java-crypto.bplaced.net";
        String timestampLocation = "Ratingen";

        // datei fuer das zertifikat/pfx-datei vom Foxit Reader
        String keystoreFilename = "Michael_Fehr.pfx";
        String keystorePassword = "123456";
        String keystoreAlias = "1"; // this alias holds the certificate
        char[] keystorePass = keystorePassword.toCharArray();

        // timestamping service
        String tsaUrl = "http://tsa.swisssign.net";
        String tsaUser = "";
        String tsaPass = "";
        // setup daten ende

        System.out.println("Timestamping PDF mit iText 7 Community Version");

        // erzeuge zielverzeichnis falls gewuenscht
        if (timestampedFilenamePath != "") {
            File file = new File(timestampedFilenamePath);
            file.mkdirs();
        }

        // erzeuge temporaere datei mit einer zusaetzlichen seite am ende
        String tempFilename = orgFilename.replace(".pdf", "_temp.pdf");
        PdfDocument document = new PdfDocument(new PdfReader(orgFilename), new PdfWriter(tempFilename));
        document.addNewPage();
        int pageCount = document.getNumberOfPages();
        // ergaenze metadaten wegen lizenzauflagen
        String metadata = "modified with iText7 Community Version, " +
                "License AGPL - GNU AFFERO GENERAL PUBLIC LICENSE, " +
                "see https://itextpdf.com/en/how-buy/legal/agpl-gnu-affero-general-public-license";
        document.getDocumentInfo().setKeywords(metadata);
        document.close();

        // einlesen des zertifikates
        System.out.println("\nZertifikatspeicher: " + keystoreFilename + " Passwort: " + keystorePassword + " Alias: " + keystoreAlias);
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(new FileInputStream(keystoreFilename), keystorePass);
        PrivateKey pk = null;
        try {
            pk = (PrivateKey) ks.getKey(keystoreAlias, keystorePass);
        } catch (NullPointerException e) {
            System.out.println("Kein Schluessel/Key unter Alias " + keystoreAlias + " gefunden, das Programm wird beendet.");
            System.exit(0);
        }
        Certificate[] chain = ks.getCertificateChain(keystoreAlias);

        // erzeugung eines ocsp-clients
        IOcspClient ocspClient = new OcspClientBouncyCastle(null);

        // erzeuge eine instanz von TSAClientBouncyCastle, eine implenetierung eines TSAClients
        // parameter: timestamp authority server url
        // nicht alle TSA benoetigen einen benutzer und ein passwort
        ITSAClient tsaClient = new TSAClientBouncyCastle(tsaUrl, tsaUser, tsaPass);
        new Timestamping_itext7()
                .sign(tempFilename, timestampedFilenamePath + timestampedFilename, chain, pk,
                        DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                        timestampReason, timestampLocation, null, ocspClient, tsaClient, 0, pageCount);

        // loesche das tempfile
        File tempFile = new File(tempFilename);
        if (tempFile.exists()) {
            tempFile.delete();
            System.out.println("Temporaere Datei geloescht: " + tempFilename);
        }

        // finale ausgabe
        System.out.println("Die signierte und mit einem Timestamp versehene PDF-Datei wurde erstellt: " + timestampedFilenamePath + timestampedFilename);

        // lizenztext
        System.out.println("\nThis program is free software: you can redistribute it and/or modify it under the terms of the" +
                "\nGNU Affero General Public License as published by the Free Software Foundation," +
                "\neither version 3 of the License, or (at your option) any later version.\n" +
                "\nThis program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;" +
                "\nwithout even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n" +
                "\nSee the GNU Affero General Public License for more details.\n" +
                "\nYou should have received a copy of the GNU Affero General Public License along with this program." +
                "\nIf not, see https://www.gnu.org/licenses/.\n" +
                "\nThe program was created with iText7 Community - get it here: https://github.com/itext/itext7 ");
    }

    public void sign(String src, String dest, Certificate[] chain, PrivateKey pk,
                     String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
                     String reason, String location, Collection<ICrlClient> crlList,
                     IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize, int signatureOnPage)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());
        System.out.println("dest = timestamp file: " + dest);

        // erzeuge das aussehen der signatur
        Rectangle rect = new Rectangle(36, 648, 300, 100);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance
                .setReason(reason)
                .setLocation(location)
                // Specify if the appearance before field is signed will be used
                // as a background for the signed field. The "false" value is the default value.
                .setReuseAppearance(false)
                .setPageRect(rect)
                .setPageNumber(signatureOnPage); // pageCount letzte seite
        signer.setFieldName("sig");

        // erzeugung der signatur
        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // signiere das dokument mit dem detached mode, CMS oder CAdES Modus
        // ergaenze den erzeugten TSAClient zur signier methode
        signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
    }
}