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


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.spnego.NegTokenInit;
import jcifs.spnego.NegTokenTarg;
import jcifs.spnego.SpnegoException;
import jcifs.spnego.SpnegoToken;
import jcifs.util.Hexdump;


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

    private boolean firstResponse = true;
    private boolean completed;

    private ASN1ObjectIdentifier[] mechs;
    private ASN1ObjectIdentifier selectedMech;
    private ASN1ObjectIdentifier[] remoteMechs;

    private boolean disableMic;
    private boolean requireMic;


    /**
     * Instance a <code>SpnegoContext</code> object by wrapping a {@link SSPContext}
     * with the same mechanism this {@link SSPContext} used.
     * 
     * @param source
     *            the {@link SSPContext} to be wrapped
     */
    SpnegoContext ( Configuration config, SSPContext source ) {
        this(config, source, source.getSupportedMechs());
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
    SpnegoContext ( Configuration config, SSPContext source, ASN1ObjectIdentifier[] mech ) {
        this.mechContext = source;
        this.mechs = mech;
        this.disableMic = !config.isEnforceSpnegoIntegrity() && config.isDisableSpnegoIntegrity();
        this.requireMic = config.isEnforceSpnegoIntegrity();
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
     * @return the mechanisms announced by the remote end
     */
    ASN1ObjectIdentifier[] getRemoteMechs () {
        return this.remoteMechs;
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
        SpnegoToken resp;
        if ( this.completed ) {
            throw new CIFSException("Already complete");
        }
        else if ( len == 0 ) {
            resp = initialToken();
        }
        else {
            resp = negotitate(inputBuf, offset, len);
        }

        if ( resp == null ) {
            return null;
        }
        return resp.toByteArray();
    }


    private SpnegoToken negotitate ( byte[] inputBuf, int offset, int len ) throws CIFSException {
        SpnegoToken spToken = getToken(inputBuf, offset, len);
        byte[] inputToken = null;
        if ( spToken instanceof NegTokenInit ) {
            NegTokenInit tinit = (NegTokenInit) spToken;
            ASN1ObjectIdentifier[] rm = tinit.getMechanisms();
            this.remoteMechs = rm;
            ASN1ObjectIdentifier prefMech = rm[ 0 ];
            // only use token if the optimistic mechanism is supported
            if ( this.mechContext.isSupported(prefMech) ) {
                inputToken = tinit.getMechanismToken();
            }
            else {
                ASN1ObjectIdentifier found = null;
                for ( ASN1ObjectIdentifier mech : rm ) {
                    if ( this.mechContext.isSupported(mech) ) {
                        found = mech;
                        break;
                    }
                }
                if ( found == null ) {
                    throw new SmbException("Server does advertise any supported mechanism");
                }
            }
        }
        else if ( spToken instanceof NegTokenTarg ) {
            NegTokenTarg targ = (NegTokenTarg) spToken;

            if ( this.firstResponse ) {
                if ( !this.mechContext.isSupported(targ.getMechanism()) ) {
                    throw new SmbException("Server chose an unsupported mechanism " + targ.getMechanism());
                }
                this.selectedMech = targ.getMechanism();
                if ( targ.getResult() == NegTokenTarg.REQUEST_MIC ) {
                    this.requireMic = true;
                }
                this.firstResponse = false;
            }
            else {
                if ( targ.getMechanism() != null && !targ.getMechanism().equals(this.selectedMech) ) {
                    throw new SmbException("Server switched mechanism");
                }
            }
            inputToken = targ.getMechanismToken();
        }
        else {
            throw new SmbException("Invalid token");
        }

        if ( spToken instanceof NegTokenTarg && this.mechContext.isEstablished() ) {
            // already established, but server hasn't completed yet
            NegTokenTarg targ = (NegTokenTarg) spToken;

            if ( targ.getResult() == NegTokenTarg.ACCEPT_INCOMPLETE && targ.getMechanismToken() == null && targ.getMechanismListMIC() != null ) {
                // this indicates that mechlistMIC is required by the server
                verifyMechListMIC(targ.getMechanismListMIC());
                return new NegTokenTarg(NegTokenTarg.UNSPECIFIED_RESULT, null, null, calculateMechListMIC());
            }
            else if ( targ.getResult() != NegTokenTarg.ACCEPT_COMPLETED ) {
                throw new SmbException("SPNEGO negotiation did not complete");
            }
            verifyMechListMIC(targ.getMechanismListMIC());
            this.completed = true;
            return null;
        }

        if ( inputToken == null ) {
            return initialToken();
        }

        byte[] mechMIC = null;
        byte[] responseToken = this.mechContext.initSecContext(inputToken, 0, inputToken.length);

        if ( spToken instanceof NegTokenTarg ) {
            NegTokenTarg targ = (NegTokenTarg) spToken;
            if ( targ.getResult() == NegTokenTarg.ACCEPT_COMPLETED && this.mechContext.isEstablished() ) {
                // server sent final token
                verifyMechListMIC(targ.getMechanismListMIC());
                if ( !this.disableMic || this.requireMic ) {
                    mechMIC = calculateMechListMIC();
                }
                this.completed = true;
            }
            else if ( this.mechContext.isMICAvailable() && ( !this.disableMic || this.requireMic ) ) {
                // we need to send our final data
                mechMIC = calculateMechListMIC();
            }
            else if ( targ.getResult() == NegTokenTarg.REJECTED ) {
                throw new SmbException("SPNEGO mechanism was rejected");
            }
        }

        if ( responseToken == null && this.mechContext.isEstablished() ) {
            return null;
        }

        return new NegTokenTarg(NegTokenTarg.UNSPECIFIED_RESULT, null, responseToken, mechMIC);
    }


    private byte[] calculateMechListMIC () throws CIFSException {
        if ( !this.mechContext.isMICAvailable() ) {
            return null;
        }

        ASN1ObjectIdentifier[] lm = this.mechs;
        byte[] ml = encodeMechs(lm);
        byte[] mechanismListMIC = this.mechContext.calculateMIC(ml);
        if ( log.isDebugEnabled() ) {
            log.debug("Out Mech list " + Arrays.toString(lm));
            log.debug("Out Mech list encoded " + Hexdump.toHexString(ml));
            log.debug("Out Mech list MIC " + Hexdump.toHexString(mechanismListMIC));
        }
        return mechanismListMIC;
    }


    private void verifyMechListMIC ( byte[] mechanismListMIC ) throws CIFSException {
        if ( this.disableMic ) {
            return;
        }

        // No MIC verification if not present and not required
        // or if the chosen mechanism is our preferred one
        if ( ( mechanismListMIC == null || !this.mechContext.supportsIntegrity() ) && this.requireMic
                && !this.mechContext.isPreferredMech(this.selectedMech) ) {
            throw new CIFSException("SPNEGO integrity is required but not available");
        }

        // otherwise we ignore the absence of a MIC
        if ( !this.mechContext.isMICAvailable() || mechanismListMIC == null ) {
            return;
        }

        try {
            ASN1ObjectIdentifier[] lm = this.mechs;
            byte[] ml = encodeMechs(lm);
            if ( log.isInfoEnabled() ) {
                log.debug("In Mech list " + Arrays.toString(lm));
                log.debug("In Mech list encoded " + Hexdump.toHexString(ml));
                log.debug("In Mech list MIC " + Hexdump.toHexString(mechanismListMIC));
            }
            this.mechContext.verifyMIC(ml, mechanismListMIC);
        }
        catch ( CIFSException e ) {
            throw new CIFSException("Failed to verify mechanismListMIC", e);
        }
    }


    /**
     * @param mechs
     * @return
     * @throws CIFSException
     */
    private static byte[] encodeMechs ( ASN1ObjectIdentifier[] mechs ) throws CIFSException {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DEROutputStream dos = new DEROutputStream(bos);
            dos.writeObject(new DERSequence(mechs));
            dos.close();
            return bos.toByteArray();
        }
        catch ( IOException e ) {
            throw new CIFSException("Failed to encode mechList", e);
        }
    }


    private SpnegoToken initialToken () throws CIFSException {
        byte[] mechToken = this.mechContext.initSecContext(new byte[0], 0, 0);
        return new NegTokenInit(this.mechs, this.mechContext.getFlags(), mechToken, null);
    }


    @Override
    public boolean isEstablished () {
        return this.completed && this.mechContext.isEstablished();
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


    @Override
    public boolean supportsIntegrity () {
        return this.mechContext.supportsIntegrity();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#isPreferredMech(org.bouncycastle.asn1.ASN1ObjectIdentifier)
     */
    @Override
    public boolean isPreferredMech ( ASN1ObjectIdentifier mech ) {
        return this.mechContext.isPreferredMech(mech);
    }


    @Override
    public byte[] calculateMIC ( byte[] data ) throws CIFSException {
        if ( !this.completed ) {
            throw new CIFSException("Context is not established");
        }
        return this.mechContext.calculateMIC(data);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#verifyMIC(byte[], byte[])
     */
    @Override
    public void verifyMIC ( byte[] data, byte[] mic ) throws CIFSException {
        if ( !this.completed ) {
            throw new CIFSException("Context is not established");
        }
        this.mechContext.verifyMIC(data, mic);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#isMICAvailable()
     */
    @Override
    public boolean isMICAvailable () {
        if ( !this.completed ) {
            return false;
        }
        return this.mechContext.isMICAvailable();
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
