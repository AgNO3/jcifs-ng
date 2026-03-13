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


import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;

import jcifs.pac.Pac;
import jcifs.pac.PacLogonInfo;
import jcifs.pac.kerberos.KerberosEncData;
import jcifs.pac.kerberos.KerberosPacAuthData;
import jcifs.pac.kerberos.KerberosToken;
import jcifs.spnego.NegTokenInit;
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



    @Test
    public void testParseSPENGOToken() throws Exception {
        /*
        negTokenInit
    mechTypes: 2 items
        MechType: 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
        MechType: 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5)
    Padding: 6
    reqFlags: c0
    mechToken: 60820b2906092a864886f71201020201006e820b1830820b14a003020105a10302010ea2…
    krb5_blob: 60820b2906092a864886f71201020201006e820b1830820b14a003020105a10302010ea2…
        KRB5 OID: 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
        krb5_tok_id: KRB5_AP_REQ (0x0001)
        Kerberos
            ap-req
                pvno: 5
                msg-type: krb-ap-req (14)
                Padding: 0
                ap-options: 20000000
                ticket
                    tkt-vno: 5
                    realm: W2K19SINGLE.SPRINGFIELD
                    sname
                        name-type: kRB5-NT-UNKNOWN (0)
                        sname-string: 2 items
                            SNameString: cifs
                            SNameString: fakeserver.w2k19single.springfield
                    enc-part
                        etype: eTYPE-ARCFOUR-HMAC-MD5 (23)
                        kvno: 5
                        cipher: 508c1fb7944c336ead0edf4536ba1ecf7102923d9dc9e0ab1d5c73d0d3bb4ca6a1120cdd…
                authenticator
                    etype: eTYPE-ARCFOUR-HMAC-MD5 (23)
                    cipher: e24ff60648505a37d583d77e20a845158b7cfe8c652ab16d0eeeb4c8700370e5d640bbdd…

         */


        Path krbConfig = Files.createTempFile("krb5", ".conf");
        Files.write(krbConfig,Arrays.asList("[libdefaults]", "allow_weak_crypto=true"));
        System.setProperty("java.security.krb5.conf", krbConfig.toString());


        byte[] keyTab = Hex.decode("0502000000620002001757324b313953494e474c452e535052494e474649454c44000463696673002266616b657365727665722e77326b313973696e676c652e737072696e676669656c64000000010000000005001700108846f7eaee8fb117ad06bdd830b7586c");

        // kerberos mech token with ticket for fake service, RC4 service key in keyTab above
        byte[] mechToken = Hex.decode("60820b3c06062b0601050502a0820b3030820b2ca018301606092a864886f71201020206092a864882f712010202a104030206c0a2820b0804820b0460820b0006092a864886f71201020201006e820aef30820aeba003020105a10302010ea20703050020000000a38204636182045f3082045ba003020105a1191b1757324b313953494e474c452e535052494e474649454c44a2353033a003020100a12c302a1b04636966731b2266616b657365727665722e77326b313973696e676c652e737072696e676669656c64a3820400308203fca003020117a103020105a28203ee048203ea508c1fb7944c336ead0edf4536ba1ecf7102923d9dc9e0ab1d5c73d0d3bb4ca6a1120cdd3bd095c7eaecff903c7cf9cff53f62f9bb447afc2d3a43898eb7c8e70b13c58951de596fd4f4b0c23d0eed2519ccb9c120e86c92a94de499f78526c3d3f6bf673c76858d53e32fb520f02f8a992a120137ba169c097e8d5f307ac1e6c0dfd998e925f49baa721f7922e40a8c7f4848231d8fd0b1b426e4ae734e78688cac8c9b67e5d4bf0f7487f0acb6d35b6fb784bff165cb9707bbb8c914f8e22dfb414a7bdebc26ca466f60222e9b85267aad8419416c2792bf80074af0935c74d296bd5edce4b479e31c8e18e62e9afa0ec832532dc8ba60bcca4dd4b56b5f64b83dfd7d80c5755983aa3be23c6fc1fa8a9fdc67dca873cb645cada8e106188c7f9d48cb7a4d628beb6460a431b60ffe99fc0f6a4aa7354007c025051663fe3d67c7a89e7d30214899e02a66c06f4cd61bbe542b1b3bf728180a310866b02b5d61003c40d7259552df7dd7c222b207904e908c3068236949cd80925def2b8fb83089cf4aabcec81b8465e261dd14a683600574f676dfe0d0e631119e1a72d44253ae82becdf21772cc76127205e72392bf478fc45042bcb7b21e1ea0e70fc9424ecb4148c2e3a0becf7573b5a945775c0f31c69063f71f066ad71a23f5410b0a6c442516cfea346517a511e371cd7e60dc453fe7bae7f05186bd010278ce4089bebb12f00b0f973225fd69c5e6f37bf8b4aa3876c42c29cb7c7ff369956ff7acfb49de8fb23017100436ea235d09d9ad7f02a73ecc8ed1fa858acc802b5ffd52d49f023d07ad659883e6b777f954120041364a53bd8e3fdaae0ad19616743945a172f91999e03e3eb39833768372974fefd8406774b2ccfbe28882ce2737268c6909dd8563f3a93dff4f5daf00926f34bf6d8fa486ed66664a09e9d2032f6eb2a45691784330b6c3134d886bcac8b524b5afaf3b566890aaa69a50d6df7587605e1f8aa7d5ad4717db6567a7e4bf68b6998afeb63098f5579544fe847d51ac2582ea0deeea4d61abc98c1a5cd161a150f5e7694d78f525a14e3c4e09a0ce49bf089b8b6e6910fa1d5b2ef0d007b855a1510071e614a04530c774e061dcdcdd5c31d93aa03a1279528234a4af7f8d0a99c89a169a1e887f83b63f37328fc97f0132bb124acbe5100830fd030bec3e8dbc18e2b0ec2ef0697966168e04dec57a16149d2ba7ae9c952a6eb2eb336b62eb6a4c5b53356d6b24e0dbd0b5fa5ca8ad37bf659775b002ba65d5fb597824378011c5edb5e6bf71be0cee261aa469329aee73ad71c9f96bf68bf3255956b630e647a37ee9ad76941ac683531c1cd9ef4017df91188b55913cb95386a508b883041c73ce4e5ec4add613d5ffbb79a8daa1350e36953e4ab04cb4beb0a482066d30820669a003020117a28206600482065ce24ff60648505a37d583d77e20a845158b7cfe8c652ab16d0eeeb4c8700370e5d640bbdd35bd3b240612ada43935932626ae5bc9cb35ade46faf8da687b8e8433b7f0168c5bb13c6e9fcde63061ecd488284720cb512793b2e951330cd211af1dc06324b8029ee6a5fd60c68c3fc3d7bc6b070de0f72629dacb3cfcf7efc1b17abea6e92494ee87d7a797a752da2f0ca3927b620d52340cc7b216a1d87f39ba971050b580efb32d4921076d37080a84882122dcfb6f5f683530e681faec88e73cf0802e16b7fdd27b2693ffa19c689b1aab8e39465d71a6aa491105928454b8d5b64233051a02e200847d9e95f7a5dd268c73c5748ed27cc8d87797a146935a5eda8682681b1928a99ca8152ef30e14996732c9713cc7f84fe693ca38c634ca06d8ea2cf7267ae7c5b8de422dbe88f24edb833b24963cb77e1ce26b9a1040185a02af9cc6e1749e162d085202428bc1ead6829355b6774527de4fef78b43ded7f859bafeba992b4d454fb317db4a7a33d857d1a296d163f09ae310fac4b4ac35066c2efaec9b75d93ea3a5cf83153a7d75b0a5c718f48f0b1114c14b918d605b0c859751d8b86a2479e4e042c9650fd55bce5a90e96db83b715eb3445d9d143cab9154019816732105dcf009a03e9d2966f7af4291a4812379e36811a7ceb17a531b19a8fe5a085d45641952b95b70c193e078d707e6618ae7541f40cdccafa92681fcb4bc22eb7c67d08a3ca97df5c3b9ef2cce3e592db2914fb7181f1d46bc8f7bf0f1ef2d6033deeb0d600da3ef340a2f3dd121ebadc72b70cad6d9cb01985f6dc67f70b85b0e7f5eb706c86663703b5c48807803ede643f580752fd68be0b7feabd8ea0b9576cb5167e0954d470bc1ca94160b9b96e30f948a77ecf0987977a251a99274aeea64bba1c9bf9dc4d3075be9cf1c10c6935104fe9f7ad6718d8439f24e26871234ecd4c5ae1491a5d87fa4581fc5eb20ecf22702a4697136748f194ef4a13ef0ed09f8873ea9eaba61710d03de38e8ac35109493b804bb958325a04bb91f46dff30db347f421819b476c3280a5fbca5219a9df2ee82d63a194b813e5b5b6a3315d28b203cb814daf1ebc8562aa8d54462ab3bac42dcc066412aa6e31b41e46e72ffbd846cdcc34dc61b09e06ac1e86debbaf52123b61c58810278143c26838ed858e889a5b41bf88155beb2bbb381e74f6c911682b1416838805d5f17c6b4742058a65429f5b4c1052704e1a3046c8d1dc5572ad62e4c7abb6cb5d76b349d737be5655dc48d1491130f140feb57a61d1c20a2f8ecd22f1802f87d83393482b4dc0c0b89d5ef60e75ee5cc09958b5624f6166c331615a935905c9c345f529567a422e665dbd1b01ce71bd05e66da06dc4cdafebd1f05911cdefc50a6a2dfb9fe85731b5caf2e81ff358553663f69301ed1474437da8f3d78c12731a194990f170f2993ec590b32677d87c2b2f64c87267791ada998047303fc749e2681fd3cb908be1be1b924f250a3434e159d6eafae6d3a21405232bc4a37bfa44149790427e6b6ed6f0c0f47efc472fdeb0cfab2005e9336415697e6b31339a6cf3aa9b490864454c65b1086d6535a735bc6cc722fe8e0d1e69b0c3a65922662a7a0e53c0b11df447c9803ceefd2e26c413cb5acc24b29e4718275601ed3ecf0305a714355298987ba5b07a7d871d4c81b6e09c0c6486f8d2ebda5fb82a926e1793a1d0fa0ce6cd999e1367ab775d5721ac0f4a490bc6c8aed3c34be3c2856c4349caaeedd6db7b21c022bd9d6a9360be13093f762ccfeab494f3fe8d69ee47aea3f987dea36c4940ac402e8a7db755a139d9a53f6414eccd56270bf5d96bced2025f8fc545f5630837209e4f3ef5652ca328339f02644948b703da31ad58053dd43aca01a4069025044709e825f87f72ef9ccf8ec544e74b537f19540f09d58f00eafc32614a89b7887a7ec261d06d460623d2adbebe561d0e866471326e7a1441464a4c21ca1eebbe29e9fbb8a1666d8b858c0c237cb2d60344b7b861cebbfa834a76f1b95a92d333bbcfe5e0405b3428434b112558744c2e261a9bf940223930a2ed443a0181d43be4149524681f91e417d36e7dd7749ffa3a30b4c35d56fed9673a638028ae3688089b3dc818f1ffb38316b65781362fe624374ccc570624f52eede4ad601aeeb0f01e12368ea8ecbfc8ccc797be6207d9140994c4a4dc4500df00f90277bbca248c246ea8f11e02697c2305787d12a0beed369ed4f57d3ec26eea5e3ee9b29959df6398848811e9e9e05677389dee2ef4b8");
        NegTokenInit negInit = new NegTokenInit(mechToken);
        byte[] krbToken = negInit.getMechanismToken();


        Path p = Files.createTempFile("fakeserver", ".keytab");
        try {
            Files.write(p, keyTab);
            KeyTab kt = KeyTab.getInstance(p.toFile());
            KerberosKey[] keys = kt.getKeys(new KerberosPrincipal("cifs/fakeserver.w2k19single.springfield@W2K19SINGLE.SPRINGFIELD", KerberosPrincipal.KRB_NT_PRINCIPAL));
            KerberosToken tok = new KerberosToken(krbToken, keys);

            KerberosEncData ed = tok.getTicket().getEncData();
            Assert.assertEquals(1, ed.getUserAuthorizations().size());

            KerberosPacAuthData pacData = (KerberosPacAuthData) ed.getUserAuthorizations().get(0);
            Pac pac = pacData.getPac();
            PacLogonInfo li = pac.getLogonInfo();
            Assert.assertEquals("test1", li.getUserName());
        } finally {
            Files.deleteIfExists(p);
            Files.deleteIfExists(krbConfig);
        }
    }
}
