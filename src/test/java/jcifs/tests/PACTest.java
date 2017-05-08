/*
 * © 2016 AgNO3 Gmbh & Co. KG
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs.tests;


import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import jcifs.pac.PACDecodingException;
import jcifs.pac.PacMac;
import jcifs.util.Hexdump;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( {
    "nls", "javadoc", "restriction"
} )
public class PACTest {

    @Test
    public void testNFold () {
        // rfc3961 test vectors
        verifyNfold(64, "012345", "be072631276b1955");
        verifyNfold(56, "password", "78a07b6caf85fa");
        verifyNfold(64, "Rough Consensus, and Running Code", "bb6ed30870b7f0e0");
        verifyNfold(168, "password", "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e");
        verifyNfold(192, "MASSACHVSETTS INSTITVTE OF TECHNOLOGY", "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b");
        verifyNfold(168, "Q", "518a54a215a8452a518a54a215a8452a518a54a215");
        verifyNfold(168, "ba", "fb25d531ae8974499f52fd92ea9857c4ba24cf297e");

        verifyNfold(64, "kerberos", "6b65726265726f73");
        verifyNfold(128, "kerberos", "6b65726265726f737b9b5b2b93132b93");
        verifyNfold(168, "kerberos", "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4");
        verifyNfold(256, "kerberos", "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4");
    }


    @Test
    public void testJavaHMAC () throws GeneralSecurityException {
        testJavaHMAC("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "Hi There", "9294727a3638bb1c13f48ef8158bfc9d");
        testJavaHMAC("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "Test With Truncation", "56461ef2342edc00f9bab995690efd4c");
        testJavaHMAC(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Hex.decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
            "56be34521d144c88dbb8c733f0e8b3f6");
    }


    private static void testJavaHMAC ( String key, String data, String expect ) throws GeneralSecurityException {
        testJavaHMAC(key, data.getBytes(StandardCharsets.US_ASCII), expect);
    }


    private static void testJavaHMAC ( String key, byte[] bytes, String expect ) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac m = Mac.getInstance("HmacMD5");
        m.init(new SecretKeySpec(Hex.decode(key), "HMAC"));
        byte[] mac = m.doFinal(bytes);
        checkBytes(Hex.decode(expect), mac);
    }


    @Test
    public void testRC4Checksum1 () throws PACDecodingException, GeneralSecurityException {
        String data = "fifteen sixteen";
        String key = "F7D3A155AF5E238A0B7A871A96BA2AB2";
        String expect = "6F65117E732E724D60FC2A9744CEAE43";
        testRC4HMac(5, data, key, expect);
    }


    @Test
    public void testRC4Checksum2 () throws PACDecodingException, GeneralSecurityException {
        String data = "seventeen eighteen nineteen twenty";
        String key = "F7D3A155AF5E238A0B7A871A96BA2AB2";
        String expect = "EB38CC97E2230F59DA4117DC5859D7EC";
        testRC4HMac(6, data, key, expect);
    }


    @Test
    public void testRC4Checksum3 () throws PACDecodingException, GeneralSecurityException {
        String data = "fifteen";
        String key = "F7D3A155AF5E238A0B7A871A96BA2AB2";
        String expect = "5BAE8D72EA64CA68189A85A5C8D80425";
        testRC4HMac(5, data, key, expect);
    }


    @Test
    public void testRC4Checksum4 () throws PACDecodingException, GeneralSecurityException {
        String data = "seventeen eighteen nineteen twenty twenty-one";
        String key = "F7D3A155AF5E238A0B7A871A96BA2AB2";
        String expect = "922A79152EF1D23032B17D8E023E8EBD";
        testRC4HMac(6, data, key, expect);
    }


    @Test
    public void testRC4Checksum5 () throws PACDecodingException, GeneralSecurityException {
        String data = "";
        String key = "F7D3A155AF5E238A0B7A871A96BA2AB2";
        String expect = "9121D44B1AD560C7A3152B3CAC453AB4";
        testRC4HMac(5, data, key, expect);
    }


    /**
     * @param data
     * @param key
     * @param expect
     * @throws GeneralSecurityException
     * @throws PACDecodingException
     */
    private static void testRC4HMac ( int usage, String data, String key, String expect ) throws GeneralSecurityException, PACDecodingException {
        byte[] keyb = Hex.decode(key);
        byte[] datab = data.getBytes(StandardCharsets.US_ASCII);
        byte[] javaMac = sun.security.krb5.internal.crypto.ArcFourHmac.calculateChecksum(keyb, usage, datab, 0, datab.length);
        byte[] mac = PacMac.calculateMacArcfourHMACMD5(usage, makeKey(keyb, 23), datab);
        checkBytes(javaMac, mac);
        checkBytes(Hex.decode(expect), javaMac);
        checkBytes(Hex.decode(expect), mac);
    }


    @Test
    public void testPACAESChecksum () throws GeneralSecurityException {
        String expect = "04EDBD6302A523C038391974";
        String data = "050000000000000001000000C001000058000000000000000A0000001A00000018020000000000000C000000780"
                + "0000038020000000000000600000010000000B0020000000000000700000014000000C00200000000000001100800CC"
                + "CCCCCCB0010000000000000000020096E604FC8FC5D201FFFFFFFFFFFFFF7FFFFFFFFFFFFFFF7FF1B9E5D0C26ED001F"
                + "1794FFB8B6FD001FFFFFFFFFFFFFF7F10001000040002001C001C0008000200000000000C0002000000000010000200"
                + "000000001400020000000000180002004F0000004F04000001020000010000001C00020020000000000000000000000"
                + "0000000000000000014001600200002000C000E00240002002800020000000000000000001002000000000000000000"
                + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000"
                + "000080000006D0062006500630068006C00650072000E000000000000000E0000004D006F007200690074007A002000"
                + "42006500630068006C00650072000000000000000000000000000000000000000000000000000000000000000000000"
                + "000000000000000000000000000000100000001020000070000000B000000000000000A00000041004400570032004B"
                + "0038005400450053005400070000000000000006000000570032004B003800410044000400000001040000000000051"
                + "5000000734F5CF10D97843CB34E535C0027A4FB8FC5D20110006D0062006500630068006C0065007200000000000000"
                + "3A0010002800500000000000000000006D0062006500630068006C00650072004000770032006B003800610064002E0"
                + "074006500730074002E00610067006E006F0033002E0065007500000000000000570032004B003800410044002E0054"
                + "004500530054002E00410047004E004F0033002E00450055001000000000000000000000000000000076FFFFFF00000"
                + "00000000000000000000000000000000000";
        String key = "B3B88E34BF46A69FC7C3FA14A09A3C918FF9BE3183FCDB995BA64E5628735C93";

        verifyAESMAC(17, expect, data, key);
    }


    public void testPACArcfourChecksum () throws GeneralSecurityException {
        String expect = "8CA2EC211EF808390C9F0C3F32D0C4AF";
        String data = "050000000000000001000000C001000058000000000000000A0000001A00000018020000000000000C000000780"
                + "0000038020000000000000600000014000000B0020000000000000700000014000000C80200000000000001100800CC"
                + "CCCCCCB00100000000000000000200EE68BFE58EC5D201FFFFFFFFFFFFFF7FFFFFFFFFFFFFFF7FF1B9E5D0C26ED001F"
                + "1794FFB8B6FD001FFFFFFFFFFFFFF7F10001000040002001C001C0008000200000000000C0002000000000010000200"
                + "000000001400020000000000180002004D0000004F04000001020000010000001C00020020000000000000000000000"
                + "0000000000000000014001600200002000C000E00240002002800020000000000000000001002000000000000000000"
                + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000"
                + "000080000006D0062006500630068006C00650072000E000000000000000E0000004D006F007200690074007A002000"
                + "42006500630068006C00650072000000000000000000000000000000000000000000000000000000000000000000000"
                + "000000000000000000000000000000100000001020000070000000B000000000000000A00000041004400570032004B"
                + "0038005400450053005400070000000000000006000000570032004B003800410044000400000001040000000000051"
                + "5000000734F5CF10D97843CB34E535C809B49E58EC5D20110006D0062006500630068006C0065007200000000000000"
                + "3A0010002800500000000000000000006D0062006500630068006C00650072004000770032006B003800610064002E0"
                + "074006500730074002E00610067006E006F0033002E0065007500000000000000570032004B003800410044002E0054"
                + "004500530054002E00410047004E004F0033002E004500550076FFFFFF0000000000000000000000000000000000000"
                + "00076FFFFFF0000000000000000000000000000000000000000";
        String key = "D6C778819F31511EE36404BAB899BD74";

        verifyArcfourHMAC(17, expect, data, key);
    }


    @Test
    public void testAES128Checksum () throws GeneralSecurityException {
        String data = "eight nine ten eleven twelve thirteen";
        String key = "9062430C8CDA3388922E6D6A509F5B7A";
        String expect = "01A4B088D45628F6946614E3";
        verifyAESHMAC(3, expect, key, data.getBytes(StandardCharsets.US_ASCII));
    }


    @Test
    public void testAES256Checksum () throws GeneralSecurityException {
        String data = "fourteen";
        String key = "B1AE4CD8462AFF1677053CC9279AAC30B796FB81CE21474DD3DDBCFEA4EC76D7";
        String expect = "E08739E3279E2903EC8E3836";
        verifyAESHMAC(4, expect, key, data.getBytes(StandardCharsets.US_ASCII));
    }


    /**
     * @param expect
     * @param data
     * @param key
     * @throws GeneralSecurityException
     */
    private static void verifyAESMAC ( int usage, String expect, String data, String key ) throws GeneralSecurityException {
        verifyAESHMAC(usage, expect, key, Hex.decode(data));
    }


    private static void verifyArcfourHMAC ( int usage, String expect, String data, String key ) throws GeneralSecurityException {
        verifyArcfourHMAC(usage, expect, key, Hex.decode(data));
    }


    /**
     * @param expect
     * @param key
     * @param bytes
     * @throws GeneralSecurityException
     */
    private static void verifyAESHMAC ( int usage, String expect, String key, byte[] bytes ) throws GeneralSecurityException {
        byte[] keybytes = Hex.decode(key);
        byte[] javaChecksum;
        if ( keybytes.length == 16 ) {
            javaChecksum = sun.security.krb5.internal.crypto.Aes128.calculateChecksum(keybytes, usage, bytes, 0, bytes.length);

        }
        else {
            javaChecksum = sun.security.krb5.internal.crypto.Aes256.calculateChecksum(keybytes, usage, bytes, 0, bytes.length);
        }

        byte[] mac = PacMac.calculateMacHMACAES(usage, makeKey(keybytes, keybytes.length == 16 ? 17 : 18), bytes);
        checkBytes(javaChecksum, mac);
        checkBytes(Hex.decode(expect), mac);
    }


    private static void verifyArcfourHMAC ( int usage, String expect, String key, byte[] bytes ) throws GeneralSecurityException {
        byte[] keybytes = Hex.decode(key);
        byte[] javaChecksum;
        if ( keybytes.length == 16 ) {
            javaChecksum = sun.security.krb5.internal.crypto.ArcFourHmac.calculateChecksum(keybytes, usage, bytes, 0, bytes.length);

        }
        else {
            javaChecksum = sun.security.krb5.internal.crypto.ArcFourHmac.calculateChecksum(keybytes, usage, bytes, 0, bytes.length);
        }

        byte[] mac = PacMac.calculateMacArcfourHMACMD5(usage, makeKey(keybytes, 23), bytes);
        checkBytes(javaChecksum, mac);
        checkBytes(Hex.decode(expect), mac);
    }


    /**
     * @param keybytes
     * @return
     */
    private static KerberosKey makeKey ( byte[] keybytes, int etype ) {
        return new KerberosKey(null, keybytes, etype, 0);
    }


    private static void checkBytes ( byte[] expect, byte[] have ) {
        if ( !Arrays.equals(expect, have) ) {
            Assert.fail(String.format("Expect: %s Have: %s", Hexdump.toHexString(expect), Hexdump.toHexString(have)));
        }
    }


    private static void verifyNfold ( int n, String string, String expect ) {
        byte[] expanded = PacMac.expandNFold(string.getBytes(StandardCharsets.US_ASCII), n / 8);
        Assert.assertEquals(expect, Hexdump.toHexString(expanded).toLowerCase(Locale.ROOT));
    }
}
