package org.bouncycastle.crypto.test;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

public class PrivateKeyFactoryTest {
    @Test
    public void testRawKey() {
        byte[] priv512 = Hex.decode("306a020100302106082a85030701010102301506092a850307010201020106082a85030701010203044204402fc35576152f6e873236608b592b4b98d0793bf5184f8dc4a99512be703716991a96061ef46aceeae5319b5c69e6fcbfa7e339207878597ce50f9b7cbf857ff1");
        try {
            PrivateKeyFactory.getRawKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(priv512)),64);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testRawKeyIncorrectLength() {

        boolean thrown = false;
        byte[] priv512 = Hex.decode("306a020100302106082a85030701010102301506092a850307010201020106082a85030701010203044204402fc35576152f6e873236608b592b4b98d0793bf5184f8dc4a99512be703716991a96061ef46aceeae5319b5c69e6fcbfa7e339207878597ce50f9b7cbf857ff1");
        try {
            PrivateKeyFactory.getRawKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(priv512)),512);
        } catch (IOException e) {
            e.printStackTrace();
        }
        catch (RuntimeException e)
        {
            e.printStackTrace();
            thrown = true;
        }
        assertEquals(true,thrown);

    }

}
