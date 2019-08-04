package com.eshare.util;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.UUID;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;

public class PGPTest {

  public static final String ID = "123";
  public static final String PASSWORD = "123456";

  public static final String PUBLIC_KEY_FILE = "pub.gpg";
  public static final String PRIVATE_KEY_FILE = "secret.gpg";

  @Test
  public void encryptAndDecryptUsingMockKey() throws IOException, PGPException {
    final String secret = UUID.randomUUID().toString();
    System.out.println("Before encryption:" + secret);
    final byte[] encrypted = PGP.encrypt(
        secret.getBytes(),
        PGPKeyUtil.findPublicKey(findFile(PUBLIC_KEY_FILE)));
    System.out.println("After encryption:" + new String(encrypted));
    //Password should be the same with certificate
    final byte[] decrypted = PGP.decrypt(
        encrypted,
        findFile(PRIVATE_KEY_FILE),
        PASSWORD);
    System.out.println("After Decryption:" + new String(decrypted));
    assertEquals(secret, new String(decrypted));
  }

  @Test
  public void encryptAndDecryptWithMultipleRecipientsUsingMockKey()
      throws IOException, PGPException {
    final String secret = UUID.randomUUID().toString();
    final byte[] encrypted = PGP.encrypt(
        secret.getBytes(),
        PGPKeyUtil.findPublicKey(findFile(PUBLIC_KEY_FILE)),
        PGPKeyUtil.findPublicKeyFromPrivate(findFile(PRIVATE_KEY_FILE)));
    //Password should be the same with certificate
    final byte[] decrypted = PGP.decrypt(
        encrypted,
        findFile(PRIVATE_KEY_FILE),
        PASSWORD);
    assertEquals(secret, new String(decrypted));
  }

  public static InputStream findFile(final String file) {
    return PGPTest.class.getClassLoader().getResourceAsStream(file);
  }


}