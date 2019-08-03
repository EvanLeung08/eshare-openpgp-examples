package com.eshare.util;

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

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Base64.Encoder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.Assert;
import org.junit.Test;


public class OpenPGPCryptoTest {

  private boolean isArmored = false;
  private String id = "evan";
  private String passwd = "123456";
  private boolean integrityCheck = true;


  private String pubKeyFile = "/tmp/pub.pgp";
  private String privKeyFile = "/tmp/secret.pgp";
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
    Encoder encoder = Base64.getEncoder();
    rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(),
        isArmored);

  }

  @Test
  public void testEncrypt() throws NoSuchProviderException, IOException, PGPException {
    FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
    FileOutputStream cipheredFileIs = new FileOutputStream(encryptedTextFile);
    PGPCryptoHelper.getInstance().encryptFile(cipheredFileIs, contentTextFile,
        PGPKeyHelper.readPublicKey(pubKeyIs), isArmored, integrityCheck);
    cipheredFileIs.close();
    pubKeyIs.close();
  }

  @Test
  public void testDecrypt() throws Exception {

    FileInputStream cipheredFileIs = new FileInputStream(encryptedTextFile);
    FileInputStream privKeyIn = new FileInputStream(privKeyFile);
    FileOutputStream contentTextFileIs = new FileOutputStream(decryptedTextFile);
    PGPCryptoHelper.getInstance()
        .decryptFile(cipheredFileIs, contentTextFileIs, privKeyIn, passwd.toCharArray());
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

    byte[] bIn = PGPCryptoHelper.getInstance().inputStreamToByteArray(plainTextInput);
    byte[] sig = PGPCryptoHelper
        .getInstance()
        .createSignature(contentTextFile, privKeyIn, signatureOut, passwd.toCharArray(), true);
    PGPCryptoHelper.getInstance().verifySignature(contentTextFile, sig, pubKeyIs);
  }

  @Test
  public void testEncryptMessage() throws IOException, PGPException, NoSuchProviderException {
    String content = "大家好，我来自中国";
    PGPPublicKey publicKey = PGPKeyHelper.readPublicKey(pubKeyFile);
    String encodeString = PGPCryptoHelper.getInstance()
        .encryptMessageAndEncode(content, publicKey);
    System.out.println(encodeString);
    Assert.assertNotNull(encodeString);

  }



}
