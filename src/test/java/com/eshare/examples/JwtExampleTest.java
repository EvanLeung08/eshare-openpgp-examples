package com.eshare.examples;

import static com.eshare.util.PGPKeyUtil.findPublicKey;
import static com.eshare.util.PGPKeyUtil.findSecretKey;
import static com.eshare.util.PGPTest.findFile;

import com.eshare.util.PGPExampleUtil;
import com.eshare.util.PGPTest;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;
import java.util.UUID;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.junit.Test;

/**
 * Created by liangyh on 2019/8/4. Email:10856214@163.com
 */
public class JwtExampleTest {

  private String pubKeyFile = "/tmp/pub.asc";
  private String privKeyFile = "/tmp/secret.asc";

  /**
   * used to fix java.security.NoSuchProviderException: no such provider: BC
   */
  static {
    try {
      Security.addProvider(new BouncyCastleProvider());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /**
   * Verify jwt token by PGP keys
   */
  @Test
  public void testJWTSigningAndVerify() throws IOException, PGPException, NoSuchProviderException {
    //Prepare PGP keys
    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(this.findFile(privKeyFile)), new JcaKeyFingerprintCalculator());
    PGPPublicKey pgpPublicKey = findPublicKey(this.findFile(pubKeyFile));
    PGPSecretKey pgpSecretKey = findSecretKey(this.findFile(privKeyFile));
    PGPPrivateKey pgpPrivateKey = PGPExampleUtil
        .findSecretKey(pgpSec, pgpSecretKey.getKeyID(), PGPTest.PASSWORD.toCharArray());

    //Convert PGP key to RSA key
    PublicKey publicKey = new JcaPGPKeyConverter().getPublicKey(pgpPublicKey);
    PrivateKey privateKey = new JcaPGPKeyConverter().getPrivateKey(pgpPrivateKey);
    //Generate jwt token
    String jwtToken = Jwts.builder()
        .setIssuer("me")
        .setSubject("Bob")
        .setAudience("you").signWith(privateKey,
            SignatureAlgorithm.PS256)
        .setId(UUID.randomUUID().toString()).compact();
    //Verify singing
    Jwts.parser()
        .setSigningKey(publicKey) // <---- publicKey, not privateKey
        .parseClaimsJws(jwtToken);

  }

  public static InputStream findFile(final String file) throws IOException {
    return FileUtils.openInputStream(new File(file));
  }
}
