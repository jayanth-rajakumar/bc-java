package org.bouncycastle.crypto.test;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import java.math.BigInteger;

public class RSAKeyParametersPartitionTest {

    //Modulus is even -> should throw IllegalArgumentException
    @Test
    public void testEvenModulus()
    {   boolean thrown=false;
        try {
            RSAKeyParameters pubParameters = new RSAKeyParameters(false, new BigInteger("24"), new BigInteger("65535"));
        }  catch (IllegalArgumentException e)
        {
            thrown=true;
        }
        assertEquals(thrown,true);
    }

    //Modulus is odd, but has small prime factors -> should throw IllegalArgumentException
    @Test
    public void testOddSmallPrimeFactorModulus()
    {   boolean thrown=false;
        try {
            RSAKeyParameters pubParameters = new RSAKeyParameters(false, new BigInteger("33"), new BigInteger("65535"));
        }  catch (IllegalArgumentException e)
        {
            thrown=true;
        }
        assertEquals(thrown,true);

    }

    //Modulus is odd, but has small prime factors -> should throw IllegalArgumentException
    @Test
    public void testOddBoundarySmallPrimeFactorModulus()
    {   boolean thrown=false;
        thrown=false;
        try {
            RSAKeyParameters pubParameters = new RSAKeyParameters(false, new BigInteger("743"), new BigInteger("65535"));
        }  catch (IllegalArgumentException e)
        {
            thrown=true;
        }
        assertEquals(thrown,true);

    }

    //Modulus is odd, and has no small prime factors -> constructor should not throw any exception.
    @Test
    public void testOddNoSmallPrimeFactorModulus()
    {   boolean thrown=false;
        try {
            RSAKeyParameters pubParameters = new RSAKeyParameters(false, new BigInteger("714401"), new BigInteger("65535"));
        }  catch (IllegalArgumentException e)
        {
            thrown=true;
        }
        assertEquals(thrown,false);

    }

    //Modulus is odd, and has no small prime factors -> constructor should not throw any exception.
    @Test
    public void testOddBoundaryNoSmallPrimeFactorModulus()
    {   boolean thrown=false;
        try {
            RSAKeyParameters pubParameters = new RSAKeyParameters(false, new BigInteger("751"), new BigInteger("65535"));
        }  catch (IllegalArgumentException e)
        {
            thrown=true;
        }
        assertEquals(thrown,false);

    }
}
