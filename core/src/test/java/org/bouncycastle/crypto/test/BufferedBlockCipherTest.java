package org.bouncycastle.crypto.test;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class BufferedBlockCipherTest {

    @Test
    public void testDataBeforeInit() {
        boolean thrown = false;
        BufferedBlockCipher b = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

    try {
        byte[] out = new byte[16];
        b.processBytes(Hex.decode("efffffeebbccbbee442299441133449922"), 0, 17, out, 0);

    } catch (IllegalStateException e) {
        thrown = true;
    }
    assertEquals(thrown,true);
    }

    @Test
    public void testInitReinit() {
        boolean thrown = false;
        BufferedBlockCipher b = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

        try {
            KeyParameter kp = new KeyParameter(Hex.decode("6E061E37F6BA4BC25346549A6AC709FE"));
            b.init(true,kp);
            b.init(false,kp);

        } catch (Exception e) {
            thrown = true;
        }
        assertEquals(thrown,false);
    }

    @Test
    public void testInitAndEncrypt() {
        boolean thrown = false;
        BufferedBlockCipher b = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

        byte[] out = new byte[16];
        int returned=0;
        try {
            KeyParameter kp = new KeyParameter(Hex.decode("6E061E37F6BA4BC25346549A6AC709FE"));
            b.init(true,kp);
            returned=b.processBytes(Hex.decode("ffffeebbccbbee4422994411334499"), 0, 15, out, 0);

        } catch (Exception e) {
            e.printStackTrace();
            thrown = true;
        }
        assertEquals(false,thrown); //No exception expected
        assertEquals(0,returned); //No output because the data was buffered
    }

    @Test
    public void testResetFromBuffered() {
        boolean thrown = false;
        BufferedBlockCipher b = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

        byte[] out = new byte[16];
        int returned=0,returned2=0;
        try {
            KeyParameter kp = new KeyParameter(Hex.decode("6E061E37F6BA4BC25346549A6AC709FE"));
            b.init(true,kp);
            returned=b.processBytes(Hex.decode("ffffeebbccbbee4422994411334499"), 0, 15, out, 0);
            b.reset();
            returned2=b.processBytes(Hex.decode("ffff"), 0, 2, out, 0);

        } catch (Exception e) {
            e.printStackTrace();
            thrown = true;
        }
        assertEquals(false,thrown); //No exception expected
        assertEquals(0,returned); //No output because the data was buffered
        assertEquals(0,returned2); //Still no output because the buffer was reset
    }

    @Test
    public void testOutputLengthExceptionOnUpdate() {
        boolean thrown = false;
        BufferedBlockCipher b = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

        byte[] out = new byte[15];
        try {
            KeyParameter kp = new KeyParameter(Hex.decode("6E061E37F6BA4BC25346549A6AC709FE"));
            b.init(true,kp);
            b.processBytes(Hex.decode("feefffeebbccbbee4422994411334499"), 0, 16, out, 0);
        } catch (OutputLengthException e) {
            thrown = true;
        }
        assertEquals(true,thrown);
    }

    @Test
    public void testOutputLengthExceptionOnUpdate2() {
        boolean thrown = false;
        BufferedBlockCipher b = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

        byte[] out2 = new byte[15];
        byte[] out = new byte[16];

        KeyParameter kp = new KeyParameter(Hex.decode("6E061E37F6BA4BC25346549A6AC709FE"));
        b.init(true,kp);
        b.processBytes(Hex.decode("feefffeebbccbbee4422994411334499"), 0, 16, out, 0);

        try {
            b.processBytes(Hex.decode("feefffeebbccbbee4422994411334499"), 0, 16, out2, 0);
        } catch (OutputLengthException e) {
            thrown = true;
        }
        assertEquals(true,thrown);
    }

    @Test
    public void testDataLengthExceptionOnFinal() {
        boolean thrown = false;
        BufferedBlockCipher b = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

        byte[] out = new byte[16];
        byte[] out2 = new byte[15];

        try {
            KeyParameter kp = new KeyParameter(Hex.decode("6E061E37F6BA4BC25346549A6AC709FE"));
            b.init(true,kp);
            b.processBytes(Hex.decode("feefffeebbccbbee442332994411334499"), 0, 17, out, 0);
            b.doFinal(out2,0);
        } catch (DataLengthException e) {
            thrown = true;
        } catch (InvalidCipherTextException e)
        {
            e.printStackTrace();
        }

        assertEquals(true,thrown);
    }

    @Test
    public void testUpdateAndFinal() {
        boolean thrown = false;
        BufferedBlockCipher b = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

        byte[] out = new byte[16];

        int returned=0;
        try {
            KeyParameter kp = new KeyParameter(Hex.decode("6E061E37F6BA4BC25346549A6AC709FE"));
            b.init(true,new ParametersWithIV(kp, Hex.decode("5F060D3716B345C253F6749ABAC10917")));
            returned=b.processBytes(Hex.decode("feefffeebbccbbee442332994411334499"), 0, 16, out, 0);
            b.doFinal(out,returned);
            b.doFinal(out,returned);
            returned=b.processBytes(Hex.decode("feefffeebbccbbee442332994411334499"), 0, 16, out, 0);
            b.reset();
        } catch (Exception e) {
            thrown = true;
            e.printStackTrace();
        }
        assertEquals(false,thrown);
        assertEquals("5714d8f58f2aee6ea9791d3c536e008d",Hex.toHexString(out)); //Verified independently
    }

    @Test
    public void testMultipleUpdates() {
        BufferedBlockCipher b = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

        byte[] out = new byte[32];

        KeyParameter kp = new KeyParameter(Hex.decode("6E061E37F6BA4BC25346549A6AC709FE"));
        b.init(true,new ParametersWithIV(kp, Hex.decode("5F060D3716B345C253F6749ABAC10917")));
        b.processBytes(Hex.decode("feefffeebbccbbee4422994411334499"), 0, 16, out, 0);
        b.processBytes(Hex.decode("feefffeebbccbbee4422994411334499"), 0, 16, out, 16);

        assertEquals("06d2c377de2de3f0b645778ec0713f19fca3fc4c0c8fc54569ee1dcf408e8c0e",Hex.toHexString(out));

    }

}
