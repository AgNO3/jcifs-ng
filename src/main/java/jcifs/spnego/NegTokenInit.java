/* jcifs smb client library in Java
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package jcifs.spnego;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import jcifs.util.Hexdump;


/**
 * SPNEGO initial token
 */
@SuppressWarnings ( "javadoc" )
public class NegTokenInit extends SpnegoToken {

    public static final int DELEGATION = 0x40;
    public static final int MUTUAL_AUTHENTICATION = 0x20;
    public static final int REPLAY_DETECTION = 0x10;
    public static final int SEQUENCE_CHECKING = 0x08;
    public static final int ANONYMITY = 0x04;
    public static final int CONFIDENTIALITY = 0x02;
    public static final int INTEGRITY = 0x01;

    private static final ASN1ObjectIdentifier SPNEGO_OID = new ASN1ObjectIdentifier(SpnegoConstants.SPNEGO_MECHANISM);

    private ASN1ObjectIdentifier[] mechanisms;

    private int contextFlags;


    public NegTokenInit () {}


    public NegTokenInit ( ASN1ObjectIdentifier[] mechanisms, int contextFlags, byte[] mechanismToken, byte[] mechanismListMIC ) {
        setMechanisms(mechanisms);
        setContextFlags(contextFlags);
        setMechanismToken(mechanismToken);
        setMechanismListMIC(mechanismListMIC);
    }


    public NegTokenInit ( byte[] token ) throws IOException {
        parse(token);
    }


    public int getContextFlags () {
        return this.contextFlags;
    }


    public void setContextFlags ( int contextFlags ) {
        this.contextFlags = contextFlags;
    }


    public boolean getContextFlag ( int flag ) {
        return ( getContextFlags() & flag ) == flag;
    }


    public void setContextFlag ( int flag, boolean value ) {
        setContextFlags(value ? ( getContextFlags() | flag ) : ( getContextFlags() & ( 0xffffffff ^ flag ) ));
    }


    public ASN1ObjectIdentifier[] getMechanisms () {
        return this.mechanisms;
    }


    public void setMechanisms ( ASN1ObjectIdentifier[] mechanisms ) {
        this.mechanisms = mechanisms;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        String mic = null;
        if ( this.getMechanismListMIC() != null ) {
            mic = Hexdump.toHexString(this.getMechanismListMIC(), 0, this.getMechanismListMIC().length);
        }
        return String.format("NegTokenInit[flags=%d,mechs=%s,mic=%s]", this.getContextFlags(), Arrays.toString(this.getMechanisms()), mic);
    }


    @Override
    public byte[] toByteArray () {
        try {
            ASN1EncodableVector fields = new ASN1EncodableVector();
            ASN1ObjectIdentifier[] mechs = getMechanisms();
            if ( mechs != null ) {
                ASN1EncodableVector vector = new ASN1EncodableVector();
                for ( int i = 0; i < mechs.length; i++ ) {
                    vector.add(mechs[ i ]);
                }
                fields.add(new DERTaggedObject(true, 0, new DERSequence(vector)));
            }
            int ctxFlags = getContextFlags();
            if ( ctxFlags != 0 ) {
                fields.add(new DERTaggedObject(true, 1, new DERBitString(ctxFlags)));
            }
            byte[] mechanismToken = getMechanismToken();
            if ( mechanismToken != null ) {
                fields.add(new DERTaggedObject(true, 2, new DEROctetString(mechanismToken)));
            }
            byte[] mechanismListMIC = getMechanismListMIC();
            if ( mechanismListMIC != null ) {
                fields.add(new DERTaggedObject(true, 3, new DEROctetString(mechanismListMIC)));
            }

            ASN1EncodableVector ev = new ASN1EncodableVector();
            ev.add(SPNEGO_OID);
            ev.add(new DERTaggedObject(true, 0, new DERSequence(fields)));
            ByteArrayOutputStream collector = new ByteArrayOutputStream();
            DEROutputStream der = new DEROutputStream(collector);
            DERApplicationSpecific derApplicationSpecific = new DERApplicationSpecific(0, ev);
            der.writeObject(derApplicationSpecific);
            return collector.toByteArray();
        }
        catch ( IOException ex ) {
            throw new IllegalStateException(ex.getMessage());
        }
    }


    @Override
    protected void parse ( byte[] token ) throws IOException {

        try ( ASN1InputStream is = new ASN1InputStream(token) ) {
            DERApplicationSpecific constructed = (DERApplicationSpecific) is.readObject();
            if ( constructed == null || !constructed.isConstructed() )
                throw new IOException(
                    "Malformed SPNEGO token " + constructed
                            + ( constructed != null ? " " + constructed.isConstructed() + " " + constructed.getApplicationTag() : "" ));

            try ( ASN1InputStream der = new ASN1InputStream(constructed.getContents()) ) {
                ASN1ObjectIdentifier spnego = (ASN1ObjectIdentifier) der.readObject();
                if ( !SPNEGO_OID.equals(spnego) ) {
                    throw new IOException("Malformed SPNEGO token, OID " + spnego);
                }
                ASN1TaggedObject tagged = (ASN1TaggedObject) der.readObject();
                if ( tagged.getTagNo() != 0 ) {
                    throw new IOException("Malformed SPNEGO token: tag " + tagged.getTagNo() + " " + tagged);
                }
                ASN1Sequence sequence = ASN1Sequence.getInstance(tagged, true);
                Enumeration<ASN1Object> fields = sequence.getObjects();
                while ( fields.hasMoreElements() ) {
                    tagged = (ASN1TaggedObject) fields.nextElement();
                    switch ( tagged.getTagNo() ) {
                    case 0:
                        sequence = ASN1Sequence.getInstance(tagged, true);
                        ASN1ObjectIdentifier[] mechs = new ASN1ObjectIdentifier[sequence.size()];
                        for ( int i = mechs.length - 1; i >= 0; i-- ) {
                            mechs[ i ] = (ASN1ObjectIdentifier) sequence.getObjectAt(i);
                        }
                        setMechanisms(mechs);
                        break;
                    case 1:
                        DERBitString ctxFlags = DERBitString.getInstance(tagged, true);
                        setContextFlags(ctxFlags.getBytes()[ 0 ] & 0xff);
                        break;
                    case 2:
                        ASN1OctetString mechanismToken = ASN1OctetString.getInstance(tagged, true);
                        setMechanismToken(mechanismToken.getOctets());
                        break;

                    case 3:
                        if ( ! ( tagged.getObject() instanceof DEROctetString ) ) {
                            break;
                        }
                    case 4:
                        ASN1OctetString mechanismListMIC = ASN1OctetString.getInstance(tagged, true);
                        setMechanismListMIC(mechanismListMIC.getOctets());
                        break;
                    default:
                        throw new IOException("Malformed token field.");
                    }
                }
            }
        }
    }

}
