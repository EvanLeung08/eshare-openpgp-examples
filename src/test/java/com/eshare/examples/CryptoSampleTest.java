package com.eshare.examples;

import com.eshare.crypto.impl.PGPKeyPairGenerator;
import com.eshare.util.PGPCryptoHelper;
import com.eshare.util.PGPKeyUtil;
import com.eshare.util.PGPTest;
import com.eshare.util.RSAKeyPairGenerator;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;


public class CryptoSampleTest {

  private boolean isArmored = true;
  private boolean integrityCheck = true;


  private String pubKeyFile = "/tmp/pub.asc";
  private String privKeyFile = "/tmp/secret.asc"
      + "";
  //create a text file to be encripted, before run the tests
  private String contentTextFile = "/tmp/content.txt";
  private String encryptedTextFile = "/tmp/encrypted-text.dat";
  private String decryptedTextFile = "/tmp/decrypted-text.txt";
  private String signatureFile = "/tmp/signature.txt";

  @Test
  public void testGenKeyPair()
      throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {

    RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();

    Security.addProvider(new BouncyCastleProvider());

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

    kpg.initialize(1024);

    KeyPair kp = kpg.generateKeyPair();

    FileOutputStream out1 = new FileOutputStream(privKeyFile);
    FileOutputStream out2 = new FileOutputStream(pubKeyFile);
    rkpg.exportKeyPair(out1, out2, kp, PGPTest.ID, PGPTest.PASSWORD.toCharArray(),
        isArmored);

  }

  @Test
  public void testBaseKeyPairGenerator()
      throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {

    PGPKeyPairGenerator pgpKeyPairGenerator = new PGPKeyPairGenerator();
    ByteArrayOutputStream outPublicKey = new ByteArrayOutputStream();
    ByteArrayOutputStream outPrivateKey = new ByteArrayOutputStream();
    pgpKeyPairGenerator.generateKeyPair(PGPTest.ID,PGPTest.PASSWORD,outPublicKey,outPrivateKey);
    System.out.println(new String(outPublicKey.toByteArray()));
    System.out.println(new String(outPrivateKey.toByteArray()));
  }

  @Test
  public void testPGPKeyPairGenerator()
      throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {

    PGPKeyPairGenerator pgpKeyPairGenerator = new PGPKeyPairGenerator();
    ByteArrayOutputStream outPublicKey = new ByteArrayOutputStream();
    ByteArrayOutputStream outPrivateKey = new ByteArrayOutputStream();
    pgpKeyPairGenerator.generateKeyPair(PGPTest.ID,PGPTest.PASSWORD,2048,outPublicKey,outPrivateKey);
    System.out.println(new String(outPublicKey.toByteArray()));
    System.out.println(new String(outPrivateKey.toByteArray()));
  }


  @Test
  public void testEncrypt() throws NoSuchProviderException, IOException, PGPException {
    FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
    FileOutputStream cipheredFileIs = new FileOutputStream(encryptedTextFile);
    PGPCryptoHelper.getInstance().encryptFile(cipheredFileIs, contentTextFile,
        PGPKeyUtil.findPublicKey(pubKeyIs), isArmored, integrityCheck);
    cipheredFileIs.close();
    pubKeyIs.close();
  }

  @Test
  public void testDecrypt() throws Exception {

    FileInputStream cipheredFileIs = new FileInputStream(encryptedTextFile);
    FileInputStream privKeyIn = new FileInputStream(privKeyFile);
    FileOutputStream contentTextFileIs = new FileOutputStream(decryptedTextFile);
    PGPCryptoHelper.getInstance()
        .decryptFile(cipheredFileIs, contentTextFileIs, privKeyIn, PGPTest.PASSWORD.toCharArray());
    cipheredFileIs.close();
    contentTextFileIs.close();
    privKeyIn.close();
  }

  @Test
  public void testSignAndVerify() throws Exception {
    FileInputStream privKeyIn = new FileInputStream(privKeyFile);
    FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
    FileInputStream plainTextInput = new FileInputStream(contentTextFile);
    FileOutputStream signatureOut = new FileOutputStream(signatureFile);

    byte[] sig = PGPCryptoHelper
        .getInstance()
        .createSignature(contentTextFile, privKeyIn, signatureOut, PGPTest.PASSWORD.toCharArray(), true);
    PGPCryptoHelper.getInstance().verifySignature(contentTextFile, sig, pubKeyIs);
  }


}
