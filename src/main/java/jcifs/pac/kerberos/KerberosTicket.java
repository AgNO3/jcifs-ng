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
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.login.LoginException;

import org.bouncycastle.asn1.*;

import jcifs.pac.ASN1Util;
import jcifs.pac.PACDecodingException;


@SuppressWarnings ( "javadoc" )
public class KerberosTicket {

    private String serverPrincipalName;
    private String serverRealm;
    private KerberosEncData encData;


    public KerberosTicket ( byte[] token, byte apOptions, KerberosKey[] keys ) throws PACDecodingException {
        if ( token.length <= 0 )
            throw new PACDecodingException("Empty kerberos ticket");

        ASN1Sequence sequence;
        try {
            try ( ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token)) ) {
                sequence = ASN1Util.as(ASN1Sequence.class, stream);
            }
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed kerberos ticket", e);
        }

        Enumeration<?> fields = sequence.getObjects();
        while ( fields.hasMoreElements() ) {
            ASN1TaggedObject tagged = ASN1Util.as(ASN1TaggedObject.class, fields);
            switch ( tagged.getTagNo() ) {
            case 0:// Kerberos version
                ASN1Integer tktvno = ASN1Util.as(ASN1Integer.class, tagged);
                if ( !tktvno.getValue().equals(new BigInteger(KerberosConstants.KERBEROS_VERSION)) ) {
                    throw new PACDecodingException("Invalid kerberos version " + tktvno);
                }
                break;
            case 1:// Realm
                DERGeneralString derRealm = ASN1Util.as(DERGeneralString.class, tagged);
                this.serverRealm = derRealm.getString();
                break;
            case 2:// Principal
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
                this.serverPrincipalName = nameBuilder.toString();
                break;
            case 3:// Encrypted part
                ASN1Sequence encSequence = ASN1Util.as(ASN1Sequence.class, tagged);
                ASN1Integer encType = ASN1Util.as(ASN1Integer.class, ASN1Util.as(ASN1TaggedObject.class, encSequence, 0));
                DEROctetString encOctets = ASN1Util.as(DEROctetString.class, ASN1Util.as(ASN1TaggedObject.class, encSequence, 2));
                byte[] crypt = encOctets.getOctets();

                if ( keys == null ) {
                    try {
                        keys = new KerberosCredentials().getKeys();
                    }
                    catch ( LoginException e ) {
                        throw new PACDecodingException("Login failure", e);
                    }
                }

                Map<Integer, KerberosKey> keysByAlgo = new HashMap<>();
                for ( KerberosKey key : keys ) {
                    keysByAlgo.put(key.getKeyType(), key);
                }

                KerberosKey serverKey = keysByAlgo.get(encType.getValue().intValue());
                if ( keysByAlgo.isEmpty() || serverKey == null ) {
                    throw new PACDecodingException("Kerberos key not found for eType " + encType.getValue());
                }

                try {
                    byte[] decrypted = KerberosEncData.decrypt(crypt, serverKey, serverKey.getKeyType());
                    this.encData = new KerberosEncData(decrypted, keysByAlgo);
                }
                catch ( GeneralSecurityException e ) {
                    throw new PACDecodingException("Decryption failed " + serverKey.getKeyType(), e);
                }
                break;
            default:
                throw new PACDecodingException("Unrecognized field " + tagged.getTagNo());
            }
        }

    }


    public String getUserPrincipalName () {
        return this.encData.getUserPrincipalName();
    }


    public String getUserRealm () {
        return this.encData.getUserRealm();
    }


    public String getServerPrincipalName () {
        return this.serverPrincipalName;
    }


    public String getServerRealm () {
        return this.serverRealm;
    }


    public KerberosEncData getEncData () {
        return this.encData;
    }

}
