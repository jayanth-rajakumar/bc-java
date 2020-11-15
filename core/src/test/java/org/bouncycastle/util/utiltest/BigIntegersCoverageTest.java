package org.bouncycastle.util.utiltest;
import com.sun.org.apache.xpath.internal.functions.FuncFalse;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;


public class BigIntegersCoverageTest {

    @Test
    public void testLengthError()
    {
        BigInteger a = new BigInteger(1, Hex.decode("ffeddecc"));
        byte[] out = new byte[10];
        boolean thrown=false;
        try {
            BigIntegers.asUnsignedByteArray(a, out, 0, 3);
        }catch(IllegalArgumentException e)
        {
            thrown=true;
        }
        assertEquals(true,thrown);
    }

    @Test
    public void testCreateRandom()
    {
        BigInteger out=BigIntegers.createRandomInRange(new BigInteger("20"),new BigInteger("20"),new SecureRandom());
        boolean thrown=false;
        try
        {
            out=BigIntegers.createRandomInRange(new BigInteger("40"),new BigInteger("30"),new SecureRandom());
        }
        catch (IllegalArgumentException e)
        {
            thrown =true;
        }
        assertEquals(true,thrown);
    }

    @Test
    public void testIntVal()
    {
        BigInteger out=new BigInteger("1234");
        assertEquals(1234,BigIntegers.intValueExact(out));

        boolean thrown= false;
        try {
            out = new BigInteger("42949672960");
            assertEquals(1234, BigIntegers.intValueExact(out));
        }catch(ArithmeticException e)
        {
            thrown=true;
        }

        assertEquals(true,thrown);
    }

    @Test
    public void testLongVal()
    {
        BigInteger out=new BigInteger("1234");
        assertEquals(1234,BigIntegers.intValueExact(out));

        boolean thrown= false;
        try {
            out = new BigInteger("42949672960");
            assertEquals(1234, BigIntegers.intValueExact(out));
        }catch(ArithmeticException e)
        {
            thrown=true;
        }

        assertEquals(true,thrown);
    }
}
