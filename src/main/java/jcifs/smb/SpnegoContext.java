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
package jcifs.smb;


import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.spnego.NegTokenInit;
import jcifs.spnego.NegTokenTarg;
import jcifs.spnego.SpnegoException;
import jcifs.spnego.SpnegoToken;


/**
 * This class used to wrap a {@link SSPContext} to provide SPNEGO feature.
 * 
 * @author Shun
 *
 */
class SpnegoContext implements SSPContext {

    private static final Logger log = LoggerFactory.getLogger(SpnegoContext.class);

    private static ASN1ObjectIdentifier SPNEGO_MECH_OID;

    static {
        try {
            SPNEGO_MECH_OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.2");
        }
        catch ( IllegalArgumentException e ) {
            log.error("Failed to initialize OID", e);
        }
    }

    private SSPContext mechContext;
    private ASN1ObjectIdentifier[] mechs;
    private boolean firstResponse;


    /**
     * Instance a <code>SpnegoContext</code> object by wrapping a {@link SSPContext}
     * with the same mechanism this {@link SSPContext} used.
     * 
     * @param source
     *            the {@link SSPContext} to be wrapped
     */
    SpnegoContext ( SSPContext source ) {
        this(source, source.getSupportedMechs());
    }


    /**
     * Instance a <code>SpnegoContext</code> object by wrapping a {@link SSPContext}
     * with specified mechanism.
     * 
     * @param source
     *            the {@link SSPContext} to be wrapped
     * @param mech
     *            the mechanism is being used for this context.
     */
    SpnegoContext ( SSPContext source, ASN1ObjectIdentifier[] mech ) {
        this.mechContext = source;
        this.mechs = mech;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#getSupportedMechs()
     */
    @Override
    public ASN1ObjectIdentifier[] getSupportedMechs () {
        return new ASN1ObjectIdentifier[] {
            SPNEGO_MECH_OID
        };
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#getFlags()
     */
    @Override
    public int getFlags () {
        return this.mechContext.getFlags();
    }


    @Override
    public boolean isSupported ( ASN1ObjectIdentifier mechanism ) {
        // prevent nesting
        return false;
    }


    /**
     * Determines what mechanism is being used for this context.
     * 
     * @return the Oid of the mechanism being used
     */
    ASN1ObjectIdentifier[] getMechs () {
        return this.mechs;
    }


    /**
     * Set what mechanism is being used for this context.
     * 
     * @param mechs
     */
    void setMechs ( ASN1ObjectIdentifier[] mechs ) {
        this.mechs = mechs;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#getNetbiosName()
     */
    @Override
    public String getNetbiosName () {
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#getSigningKey()
     */
    @Override
    public byte[] getSigningKey () throws CIFSException {
        return this.mechContext.getSigningKey();
    }


    /**
     * Initialize the GSSContext to provide SPNEGO feature.
     * 
     * @param inputBuf
     * @param offset
     * @param len
     * @return response token
     */
    @Override
    public byte[] initSecContext ( byte[] inputBuf, int offset, int len ) throws CIFSException {
        if ( len == 0 ) {
            return initialToken();
        }

        return negotitate(inputBuf, offset, len);
    }


    private byte[] negotitate ( byte[] inputBuf, int offset, int len ) throws CIFSException {
        SpnegoToken spToken = getToken(inputBuf, offset, len);

        if ( this.firstResponse && spToken instanceof NegTokenTarg ) {
            NegTokenTarg targ = (NegTokenTarg) spToken;
            if ( !this.mechContext.isSupported(targ.getMechanism()) ) {
                throw new SmbException("Server chose an unsupported mechanism " + targ.getMechanism());
            }
            this.firstResponse = false;
        }

        ASN1ObjectIdentifier currentMech = null;
        byte[] mechToken = spToken.getMechanismToken();
        if ( mechToken == null ) {
            return initialToken();
        }

        mechToken = this.mechContext.initSecContext(mechToken, 0, mechToken.length);
        if ( mechToken != null ) {
            int result = NegTokenTarg.ACCEPT_INCOMPLETE;
            byte[] mechMIC = null;
            if ( spToken instanceof NegTokenTarg ) {
                NegTokenTarg targ = (NegTokenTarg) spToken;
                if ( targ.getResult() == NegTokenTarg.ACCEPT_COMPLETED && this.mechContext.isEstablished() ) {
                    result = NegTokenTarg.ACCEPT_COMPLETED;
                    if ( targ.getMechanism() != null ) {
                        currentMech = targ.getMechanism();
                    }
                    mechMIC = targ.getMechanismListMIC();
                }
                else if ( targ.getResult() == NegTokenTarg.REJECTED ) {
                    throw new SmbException("SPNEGO mechanism was rejected");
                }
            }
            return new NegTokenTarg(result, currentMech, mechToken, mechMIC).toByteArray();
        }
        return null;
    }


    private byte[] initialToken () throws CIFSException {
        byte[] mechToken = this.mechContext.initSecContext(new byte[0], 0, 0);
        return new NegTokenInit(this.mechs, this.mechContext.getFlags(), mechToken, null).toByteArray();
    }


    @Override
    public boolean isEstablished () {
        return this.mechContext.isEstablished();
    }


    private static SpnegoToken getToken ( byte[] token, int off, int len ) throws SpnegoException {
        byte[] b = new byte[len];
        if ( off == 0 && token.length == len ) {
            b = token;
        }
        else {
            System.arraycopy(token, off, b, 0, len);
        }
        return getToken(b);
    }


    private static SpnegoToken getToken ( byte[] token ) throws SpnegoException {
        SpnegoToken spnegoToken = null;
        try {
            switch ( token[ 0 ] ) {
            case (byte) 0x60:
                spnegoToken = new NegTokenInit(token);
                break;
            case (byte) 0xa1:
                spnegoToken = new NegTokenTarg(token);
                break;
            default:
                throw new SpnegoException("Invalid token type");
            }
            return spnegoToken;
        }
        catch ( IOException e ) {
            throw new SpnegoException("Invalid token");
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        return "SPNEGO[" + this.mechContext + "]";
    }


    /**
     * 
     */
    @Override
    public void dispose () throws CIFSException {
        this.mechContext.dispose();
    }
}
