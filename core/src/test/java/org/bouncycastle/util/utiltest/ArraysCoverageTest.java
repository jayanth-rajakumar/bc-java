package org.bouncycastle.util.utiltest;
import org.bouncycastle.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class ArraysCoverageTest {
    @Test
    public void testCompareUnsigned()
    {
        byte[] b1={1,2};
        byte[] b2={3,4};
        byte[] b3={1,2,3,4};
        byte[] b4={1,2,3,4};
        assertEquals(0,Arrays.compareUnsigned(b1,b1));
        assertEquals(1,Arrays.compareUnsigned(b1,null));
        assertEquals(-1,Arrays.compareUnsigned(null,b1));
        assertEquals(-1,Arrays.compareUnsigned(b1,b2));
        assertEquals(1,Arrays.compareUnsigned(b2,b1));
        assertEquals(1,Arrays.compareUnsigned(b3,b1));
        assertEquals(-1,Arrays.compareUnsigned(b1,b3));
        assertEquals(0,Arrays.compareUnsigned(b4,b3));
    }

    @Test
    public void testBoolContains()
    {
        boolean a[]={true,true};
        assertEquals(false,Arrays.contains(a,false));
        assertEquals(true,Arrays.contains(a,true));

    }

    @Test
    public void testByteContains()
    {
        byte a[]={4,5};
        assertEquals(false,Arrays.contains(a,(byte)6));
        assertEquals(true,Arrays.contains(a,(byte)4));
    }

    @Test
    public void testCharContains()
    {
        char a[]={'a','v'};
        assertEquals(false,Arrays.contains(a,'c'));
        assertEquals(true,Arrays.contains(a,'v'));
    }

    @Test
    public void testIntContains()
    {
        int a[]={4,5};
        assertEquals(false,Arrays.contains(a,6));
        assertEquals(true,Arrays.contains(a,4));
    }

    @Test
    public void testLongContains()
    {
        long a[]={45353533,5};
        assertEquals(false,Arrays.contains(a,6));
        assertEquals(true,Arrays.contains(a,45353533));
    }

    @Test
    public void testShortContains()
    {
        short a[]={4,5};
        assertEquals(false,Arrays.contains(a,(short)6));
        assertEquals(true,Arrays.contains(a,(short)4));
    }


    @Test
    public void testShortAppend()
    {
        short a[]={4,5};
        short[] rs=Arrays.append(a,(short)6);
        assertEquals(true,rs.length==3 && rs[0]==4 && rs[1]==5 &&rs[2]==6 );
        short b[]=null;
        rs=Arrays.append(b,(short)6);
        assertEquals(true,rs.length==1 && rs[0]==6);
    }
    @Test
    public void testIntAppend()
    {
        int a[]={4,5};
        int[] rs=Arrays.append(a,(short)6);
        assertEquals(true,rs.length==3 && rs[0]==4 && rs[1]==5 &&rs[2]==6 );
        int b[]=null;
        rs=Arrays.append(b,(int)6);
        assertEquals(true,rs.length==1 && rs[0]==6);
    }

    @Test
    public void testIntPrepend()
    {
        int a[]={4,5};
        int[] rs=Arrays.prepend(a,(int)6);
        assertEquals(true,rs.length==3 && rs[0]==6 && rs[1]==4 &&rs[2]==5 );
        int b[]=null;
        rs=Arrays.prepend(b,(int)6);
        assertEquals(true,rs.length==1 && rs[0]==6);
    }

    @Test
    public void testHashCode()
    {
        char a[]={'d','f','2','$'};
        Arrays.hashCode(a);
        a=null;
        assertEquals(0,Arrays.hashCode(a));

        int b[][]={{12,432,4334,55},{32,43,55}};
        Arrays.hashCode(b);

        int c[]={43,55,23,454,22};
        Arrays.hashCode(c);
        Arrays.hashCode(c,1,2);
        c=null;
        assertEquals(0,Arrays.hashCode(c));
        assertEquals(0,Arrays.hashCode(c,0,0));

        long d[]={43,55,23,454,22};
        Arrays.hashCode(c);
        Arrays.hashCode(c,1,2);
        c=null;
        assertEquals(0,Arrays.hashCode(c));
        assertEquals(0,Arrays.hashCode(c,0,0));



    }


}
