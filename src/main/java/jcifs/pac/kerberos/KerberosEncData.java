/*
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
package jcifs.pac.kerberos;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.*;

import jcifs.pac.ASN1Util;
import jcifs.pac.PACDecodingException;
import jcifs.util.Encdec;


@SuppressWarnings ( "javadoc" )
public class KerberosEncData {

    private String userRealm;
    private String userPrincipalName;
    private ArrayList<InetAddress> userAddresses;
    private List<KerberosAuthData> userAuthorizations;


    public KerberosEncData ( byte[] token, Map<Integer, KerberosKey> keys ) throws PACDecodingException {
        ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token));
        ASN1TaggedObject derToken;
        try {
            derToken = ASN1Util.as(ASN1TaggedObject.class, stream);
            if ( derToken.getTagClass() != BERTags.APPLICATION )
                throw new PACDecodingException("Malformed kerberos ticket");
            stream.close();
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed kerberos ticket", e);
        }

        ASN1Sequence sequence;
        try {
            sequence = ASN1Util.as(ASN1Sequence.class, derToken.getBaseObject());
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed kerberos ticket", e);
        }

        Enumeration<?> fields = sequence.getObjects();
        while ( fields.hasMoreElements() ) {
            ASN1TaggedObject tagged = ASN1Util.as(ASN1TaggedObject.class, fields);

            switch ( tagged.getTagNo() ) {
            case 0: // Ticket Flags
                break;
            case 1: // Key
                break;
            case 2: // Realm
                DERGeneralString derRealm = ASN1Util.as(DERGeneralString.class, tagged);
                this.userRealm = derRealm.getString();
                break;
            case 3: // Principal
                ASN1Sequence principalSequence = ASN1Util.as(ASN1Sequence.class, tagged);
                ASN1Sequence nameSequence = ASN1Util.as(ASN1Sequence.class, ASN1Util.as(ASN1TaggedObject.class, principalSequence, 1));

                StringBuilder nameBuilder = new StringBuilder();
                Enumeration<?> parts = nameSequence.getObjects();
                while ( parts.hasMoreElements() ) {
                    Object part = parts.nextElement();
                    DERGeneralString stringPart = ASN1Util.as(DERGeneralString.class, part);
                    nameBuilder.append(stringPart.getString());
                    if ( parts.hasMoreElements() )
                        nameBuilder.append('/');
                }
                this.userPrincipalName = nameBuilder.toString();
                break;
            case 4: // Transited Encoding
                break;
            case 5: // Kerberos Time
                // DERGeneralizedTime derTime = KerberosUtil.readAs(tagged,
                // DERGeneralizedTime.class);
                break;
            case 6: // Kerberos Time
                // DERGeneralizedTime derTime = KerberosUtil.readAs(tagged,
                // DERGeneralizedTime.class);
                break;
            case 7: // Kerberos Time
                // DERGeneralizedTime derTime = KerberosUtil.readAs(tagged,
                // DERGeneralizedTime.class);
                break;
            case 8: // Kerberos Time
                // DERGeneralizedTime derTime = KerberosUtil.readAs(tagged,
                // DERGeneralizedTime.class);
                break;
            case 9: // Host Addresses
                ASN1Sequence adressesSequence = ASN1Util.as(ASN1Sequence.class, tagged);
                Enumeration<?> adresses = adressesSequence.getObjects();
                while ( adresses.hasMoreElements() ) {
                    ASN1Sequence addressSequence = ASN1Util.as(ASN1Sequence.class, adresses);
                    ASN1Integer addressType = ASN1Util.as(ASN1Integer.class, addressSequence, 0);
                    DEROctetString addressOctets = ASN1Util.as(DEROctetString.class, addressSequence, 1);

                    this.userAddresses = new ArrayList<>();
                    if ( addressType.getValue().intValue() == KerberosConstants.AF_INTERNET ) {
                        InetAddress userAddress = null;
                        try {
                            userAddress = InetAddress.getByAddress(addressOctets.getOctets());
                        }
                        catch ( UnknownHostException e ) {}
                        this.userAddresses.add(userAddress);
                    }
                }
                break;
            case 10: // Authorization Data
                ASN1Sequence authSequence = ASN1Util.as(ASN1Sequence.class, tagged);

                this.userAuthorizations = new ArrayList<>();
                Enumeration<?> authElements = authSequence.getObjects();
                while ( authElements.hasMoreElements() ) {
                    ASN1Sequence authElement = ASN1Util.as(ASN1Sequence.class, authElements);
                    ASN1Integer authType = ASN1Util.as(ASN1Integer.class, ASN1Util.as(ASN1TaggedObject.class, authElement, 0));
                    DEROctetString authData = ASN1Util.as(DEROctetString.class, ASN1Util.as(ASN1TaggedObject.class, authElement, 1));

                    this.userAuthorizations.addAll(KerberosAuthData.parse(authType.getValue().intValue(), authData.getOctets(), keys));
                }
                break;
            default:
                throw new PACDecodingException("Unknown field " + tagged.getTagNo());
            }
        }
    }


    public static byte[] decrypt ( byte[] data, Key key, int type ) throws GeneralSecurityException {
        Cipher cipher = null;
        byte[] decrypt = null;

        switch ( type ) {
        case KerberosConstants.DES_ENC_TYPE:
            decrypt = decryptDES(data, key, cipher);
            break;
        case KerberosConstants.RC4_ENC_TYPE:
            decrypt = decryptRC4(data, key);
            break;
        default:
            throw new GeneralSecurityException("Unsupported encryption type " + type);
        }
        return decrypt;
    }


    /**
     * @param data
     * @param key
     * @return
     * @throws GeneralSecurityException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    private static byte[] decryptRC4 ( byte[] data, Key key ) throws GeneralSecurityException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher;
        byte[] decrypt;
        byte[] code = new byte[4];
        Encdec.enc_uint32le(2, code, 0);
        byte[] codeHmac = getHmac(code, key.getEncoded());

        byte[] dataChecksum = new byte[KerberosConstants.CHECKSUM_SIZE];
        System.arraycopy(data, 0, dataChecksum, 0, KerberosConstants.CHECKSUM_SIZE);

        byte[] dataHmac = getHmac(dataChecksum, codeHmac);
        SecretKeySpec dataKey = new SecretKeySpec(dataHmac, KerberosConstants.RC4_ALGORITHM);

        cipher = Cipher.getInstance(KerberosConstants.RC4_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, dataKey);

        int plainDataLength = data.length - KerberosConstants.CHECKSUM_SIZE;
        byte[] plainData = cipher.doFinal(data, KerberosConstants.CHECKSUM_SIZE, plainDataLength);

        byte[] plainDataChecksum = getHmac(plainData, codeHmac);
        if ( plainDataChecksum.length >= KerberosConstants.CHECKSUM_SIZE )
            for ( int i = 0; i < KerberosConstants.CHECKSUM_SIZE; i++ )
                if ( plainDataChecksum[ i ] != data[ i ] )
                    throw new GeneralSecurityException("Checksum failed while decrypting.");

        int decryptLength = plainData.length - KerberosConstants.CONFOUNDER_SIZE;
        decrypt = new byte[decryptLength];
        System.arraycopy(plainData, KerberosConstants.CONFOUNDER_SIZE, decrypt, 0, decryptLength);
        return decrypt;
    }


    /**
     * @param data
     * @param key
     * @param cipher
     * @return
     * @throws GeneralSecurityException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    private static byte[] decryptDES ( byte[] data, Key key, Cipher cipher )
            throws GeneralSecurityException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] decrypt;
        try {
            cipher = Cipher.getInstance("DES/CBC/NoPadding");
        }
        catch ( GeneralSecurityException e ) {
            throw new GeneralSecurityException("Checksum failed while decrypting.");
        }
        byte[] ivec = new byte[8];
        IvParameterSpec params = new IvParameterSpec(ivec);

        SecretKeySpec skSpec = new SecretKeySpec(key.getEncoded(), "DES");
        SecretKey sk = skSpec;

        cipher.init(Cipher.DECRYPT_MODE, sk, params);

        byte[] result;
        result = cipher.doFinal(data);

        decrypt = new byte[result.length];
        System.arraycopy(result, 0, decrypt, 0, result.length);

        int tempSize = decrypt.length - 24;

        byte[] output = new byte[tempSize];
        System.arraycopy(decrypt, 24, output, 0, tempSize);

        decrypt = output;
        return decrypt;
    }


    private static byte[] getHmac ( byte[] data, byte[] key ) throws GeneralSecurityException {
        Key macKey = new SecretKeySpec(key.clone(), KerberosConstants.HMAC_ALGORITHM);
        Mac mac = Mac.getInstance(KerberosConstants.HMAC_ALGORITHM);
        mac.init(macKey);
        return mac.doFinal(data);
    }


    public String getUserRealm () {
        return this.userRealm;
    }


    public String getUserPrincipalName () {
        return this.userPrincipalName;
    }


    public ArrayList<InetAddress> getUserAddresses () {
        return this.userAddresses;
    }


    public List<KerberosAuthData> getUserAuthorizations () {
        return this.userAuthorizations;
    }

}
