package com.eshare.crypto.impl;

import com.eshare.crypto.KeyPairGenerator;
import com.eshare.crypto.MessageEncryptor;
import com.eshare.crypto.MessageSigner;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The Factory providing a library independent simple access to the  PGP API
 *
 * @author Evan Leung
 */
public final class PGPWrapperFactory {

  private PGPWrapperFactory() {
    super();
  }

  /**
   * initializes the security provider
   */
  public static void init() {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   *
   * @return a message encryptor instance
   */
  public static MessageEncryptor getEncyptor() {
    return new PGPMessageEncryptor();
  }

  /**
   *
   * @return a key pair generator instance
   */
  public static KeyPairGenerator getKeyPairGenerator() {
    return new PGPKeyPairGenerator();
  }

  /**
   *
   * @return a message signer instance
   */
  public static MessageSigner getSigner() {
    return new PGPMessageSigner();
  }

}
