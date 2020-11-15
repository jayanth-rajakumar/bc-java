package org.bouncycastle.crypto.test;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;

public class RSADigestSignerCoverageTest {

    BigInteger rsaPubMod,rsaPubExp,rsaPrivMod,rsaPrivDP,rsaPrivDQ,rsaPrivExp,rsaPrivP,rsaPrivQ,rsaPrivQinv;
    RSAKeyParameters rsaPublic;
    RSAPrivateCrtKeyParameters rsaPrivate;
    @Before
    public void initKeyParams()
    {
        rsaPubMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
        rsaPubExp = new BigInteger(Base64.decode("EQ=="));
        rsaPrivMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
        rsaPrivDP = new BigInteger(Base64.decode("JXzfzG5v+HtLJIZqYMUefJfFLu8DPuJGaLD6lI3cZ0babWZ/oPGoJa5iHpX4Ul/7l3s1PFsuy1GhzCdOdlfRcQ=="));
        rsaPrivDQ = new BigInteger(Base64.decode("YNdJhw3cn0gBoVmMIFRZzflPDNthBiWy/dUMSRfJCxoZjSnr1gysZHK01HteV1YYNGcwPdr3j4FbOfri5c6DUQ=="));
        rsaPrivExp = new BigInteger(Base64.decode("DxFAOhDajr00rBjqX+7nyZ/9sHWRCCp9WEN5wCsFiWVRPtdB+NeLcou7mWXwf1Y+8xNgmmh//fPV45G2dsyBeZbXeJwB7bzx9NMEAfedchyOwjR8PYdjK3NpTLKtZlEJ6Jkh4QihrXpZMO4fKZWUm9bid3+lmiq43FwW+Hof8/E="));
        rsaPrivP = new BigInteger(Base64.decode("AJ9StyTVW+AL/1s7RBtFwZGFBgd3zctBqzzwKPda6LbtIFDznmwDCqAlIQH9X14X7UPLokCDhuAa76OnDXb1OiE="));
        rsaPrivQ = new BigInteger(Base64.decode("AM3JfD79dNJ5A3beScSzPtWxx/tSLi0QHFtkuhtSizeXdkv5FSba7lVzwEOGKHmW829bRoNxThDy4ds1IihW1w0="));
        rsaPrivQinv = new BigInteger(Base64.decode("Lt0g7wrsNsQxuDdB8q/rH8fSFeBXMGLtCIqfOec1j7FEIuYA/ACiRDgXkHa0WgN7nLXSjHoy630wC5Toq8vvUg=="));
        rsaPublic = new RSAKeyParameters(false, rsaPubMod, rsaPubExp);
        rsaPrivate = new RSAPrivateCrtKeyParameters(rsaPrivMod, rsaPubExp, rsaPrivExp, rsaPrivP, rsaPrivQ, rsaPrivDP, rsaPrivDQ, rsaPrivQinv);
    }

    @Test
    public void testGetAlgName()
    {
        RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());
        assertEquals(signer.getAlgorithmName(),"SHA-1withRSA");
    }

    @Test
    public void testWithRandom()
    {
        RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());
        signer.init(true, new ParametersWithRandom(rsaPrivate,new SecureRandom()));
        assertEquals(signer.getAlgorithmName(),"SHA-1withRSA");

    }

    @Test
    public void testWrongKeyType()
    {
        boolean thrown=false;
        RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());
        try {
            signer.init(true, rsaPublic);
        }catch(IllegalArgumentException e)
        {
            thrown=true;
        }
        assertEquals(thrown,true);

        thrown=false;
        try {
            signer.init(false, rsaPrivate);
        }catch(IllegalArgumentException e)
        {
            thrown=true;
        }
        assertEquals(thrown,true);
    }

    @Test
    public void testDigestUpdate()
    {
        RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());
        signer.init(true, rsaPrivate);

        byte x=0;
        signer.update(x);
        boolean thrown=false;
        try {
            signer.generateSignature();
        }catch (CryptoException e)
        {
            thrown=true;
        }
        assertEquals(false,thrown);
    }

    @Test
    public void testGenSigBeforeInit()
    {
        RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());
        signer.init(false, rsaPublic);
        boolean thrown=false;
        try
        {
            signer.generateSignature();
        }
        catch (IllegalStateException e)
        {
            thrown=true;
        }
        catch (CryptoException e)
        {
            thrown=false;
        }
        assertEquals(true,thrown);

    }

    @Test
    public void testVerifySigBeforeInit()
    {
        RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());
        signer.init(true, rsaPrivate);
        boolean thrown=false;
        try
        {
            signer.verifySignature(new byte[16]);
        }
        catch (IllegalStateException e)
        {
            thrown=true;
        }

        assertEquals(true,thrown);

    }

    @Test
    public void testDiffSigLen()
    {
        RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());

        signer.init(true, rsaPrivate);
        byte[] msg = new byte[] { 1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23 };
        signer.update(msg, 0, msg.length);

        byte[] sig=null;
        try {
             sig= signer.generateSignature();
        }catch(CryptoException e)
        {
            e.printStackTrace();
        }

        signer = new RSADigestSigner(new SHA1Digest(),  X509ObjectIdentifiers.id_SHA1);
        signer.init(false, rsaPublic);
        byte[] msg2=new byte[msg.length+1];
        System.arraycopy(msg,0,msg2,0,msg.length);
        signer.update(msg2, 0, msg.length+1);

        assertEquals(false,signer.verifySignature(sig));

    }






}
