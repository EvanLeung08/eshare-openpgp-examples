package com.eshare.crypto;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Definition of a simple PGP key signer
 *
 * @author Evan Leung
 */
public interface KeySigner {

  /**
   * TODO no implementation present yet
   *
   * @param publicKey
   * @param privateKey
   * @param targetStream
   * @return
   */
  boolean signKey(InputStream publicKey, InputStream privateKey, OutputStream targetStream);

}
