package com.eshare.util;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;

import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;

public class PGPTest {

  public static final String PASSPHRASE = "unittest";

  public static final String PUBLIC_KEY_FILE = "pub.pgp";
  public static final String PRIVATE_KEY_FILE = "secret.pgp";

  @Test
  public void encryptAndDecryptUsingMockKey() throws IOException, PGPException {
    final String secret = UUID.randomUUID().toString();
    System.out.println("Before encryption:" + secret);
    final byte[] encrypted = PGP.encrypt(
        secret.getBytes(),
        KeyUtil.findPublicKey(findFile(PUBLIC_KEY_FILE)));
    System.out.println("After encryption:" + new String(encrypted));
    final byte[] decrypted = PGP.decrypt(
        encrypted,
        findFile(PRIVATE_KEY_FILE),
        PASSPHRASE);
    System.out.println("After Decryption:" + new String(decrypted));
    assertEquals(secret, new String(decrypted));
  }

  @Test
  public void encryptAndDecryptWithMultipleRecipientsUsingMockKey()
      throws IOException, PGPException {
    final String secret = UUID.randomUUID().toString();
    final byte[] encrypted = PGP.encrypt(
        secret.getBytes(),
        KeyUtil.findPublicKey(findFile(PUBLIC_KEY_FILE)),
        KeyUtil.findPublicKeyFromPrivate(findFile(PRIVATE_KEY_FILE)));
    final byte[] decrypted = PGP.decrypt(
        encrypted,
        findFile(PRIVATE_KEY_FILE),
        PASSPHRASE);
    assertEquals(secret, new String(decrypted));
  }

  public static InputStream findFile(final String file) {
    return PGPTest.class.getClassLoader().getResourceAsStream(file);
  }
}