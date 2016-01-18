package jcifs.smb;


import java.io.IOException;

import org.apache.log4j.Logger;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

import jcifs.CIFSException;
import jcifs.spnego.NegTokenInit;
import jcifs.spnego.NegTokenTarg;
import jcifs.spnego.SpnegoToken;


/**
 * This class used to wrap a {@link GSSContext} to provide SPNEGO feature.
 * 
 * @author Shun
 *
 */
class SpnegoContext {

    private static final Logger log = Logger.getLogger(SpnegoContext.class);

    private Kerb5Context context;
    private Oid[] mechs;


    /**
     * 
     */
    public SpnegoContext ( NtlmContext ctx ) {

    }


    /**
     * Instance a <code>SpnegoContext</code> object by wrapping a {@link GSSContext}
     * with the same mechanism this {@link GSSContext} used.
     * 
     * @param source
     *            the {@link GSSContext} to be wrapped
     * @throws GSSException
     */
    SpnegoContext ( Kerb5Context source ) throws GSSException {
        this(source, new Oid[] {
            source.getGSSContext().getMech()
        });
    }


    /**
     * Instance a <code>SpnegoContext</code> object by wrapping a {@link GSSContext}
     * with specified mechanism.
     * 
     * @param source
     *            the {@link GSSContext} to be wrapped
     * @param mech
     *            the mechanism is being used for this context.
     */
    SpnegoContext ( Kerb5Context source, Oid[] mech ) {
        this.context = source;
        this.mechs = mech;
    }


    /**
     * Determines what mechanism is being used for this context.
     * 
     * @return the Oid of the mechanism being used
     */
    Oid[] getMechs () {
        return this.mechs;
    }


    /**
     * Set what mechanism is being used for this context.
     * 
     * @param mechs
     */
    void setMechs ( Oid[] mechs ) {
        this.mechs = mechs;
    }


    /**
     * Get the GSSContext initialized for SPNEGO.
     * 
     * @return the gsscontext
     */
    GSSContext getGSSContext () {
        return this.context.getGSSContext();
    }


    /**
     * Initialize the GSSContext to provide SPNEGO feature.
     * 
     * @param inputBuf
     * @param offset
     * @param len
     * @return
     * @throws GSSException
     */
    byte[] initSecContext ( byte[] inputBuf, int offset, int len ) throws GSSException, CIFSException {
        byte[] ret = null;
        if ( len == 0 ) {
            byte[] mechToken = this.context.getGSSContext().initSecContext(inputBuf, offset, len);
            int contextFlags = 0;
            if ( this.getGSSContext().getCredDelegState() ) {
                contextFlags |= NegTokenInit.DELEGATION;
            }
            if ( this.getGSSContext().getMutualAuthState() ) {
                contextFlags |= NegTokenInit.MUTUAL_AUTHENTICATION;
            }
            if ( this.getGSSContext().getReplayDetState() ) {
                contextFlags |= NegTokenInit.REPLAY_DETECTION;
            }
            if ( this.getGSSContext().getSequenceDetState() ) {
                contextFlags |= NegTokenInit.SEQUENCE_CHECKING;
            }
            if ( this.getGSSContext().getAnonymityState() ) {
                contextFlags |= NegTokenInit.ANONYMITY;
            }
            if ( this.getGSSContext().getConfState() ) {
                contextFlags |= NegTokenInit.CONFIDENTIALITY;
            }
            if ( this.getGSSContext().getIntegState() ) {
                contextFlags |= NegTokenInit.INTEGRITY;
            }
            ret = new NegTokenInit(this.mechs, contextFlags, mechToken, null).toByteArray();
        }
        else {
            SpnegoToken spToken = getToken(inputBuf, offset, len);
            Oid currentMech = this.getGSSContext().getMech();
            if ( spToken instanceof NegTokenTarg ) {
                NegTokenTarg targ = (NegTokenTarg) spToken;
                if ( targ.getMechanism() != null && !targ.getMechanism().equals(this.getGSSContext().getMech()) ) {
                    log.error("Selected mech does not match the context " + targ.getMechanism());
                }
            }

            byte[] mechToken = spToken.getMechanismToken();
            mechToken = this.getGSSContext().initSecContext(mechToken, 0, mechToken.length);
            if ( mechToken != null ) {
                int result = NegTokenTarg.ACCEPT_INCOMPLETE;
                byte[] mechMIC = null;
                if ( spToken instanceof NegTokenTarg ) {
                    NegTokenTarg targ = (NegTokenTarg) spToken;
                    if ( targ.getResult() == NegTokenTarg.ACCEPT_COMPLETED && this.getGSSContext().isEstablished() ) {
                        result = NegTokenTarg.ACCEPT_COMPLETED;
                        if ( targ.getMechanism() != null ) {
                            currentMech = targ.getMechanism();
                        }
                        mechMIC = targ.getMechanismListMIC();
                    }
                    else if ( targ.getResult() == NegTokenTarg.REJECTED ) {
                        throw new CIFSException("SPNEGO mechanism was rejected");
                    }
                }
                ret = new NegTokenTarg(result, currentMech, mechToken, mechMIC).toByteArray();
            }
        }
        return ret;
    }


    /**
     * 
     * 
     * @return
     */
    public boolean isEstablished () {
        return this.getGSSContext().isEstablished();
    }


    private static SpnegoToken getToken ( byte[] token, int off, int len ) throws GSSException {
        byte[] b = new byte[len];
        if ( off == 0 && token.length == len ) {
            b = token;
        }
        else {
            System.arraycopy(token, off, b, 0, len);
        }
        return getToken(b);
    }


    private static SpnegoToken getToken ( byte[] token ) throws GSSException {
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
                throw new GSSException(GSSException.DEFECTIVE_TOKEN);
            }
            return spnegoToken;
        }
        catch ( IOException e ) {
            throw new GSSException(GSSException.FAILURE);
        }
    }


    /**
     * 
     */
    public void dispose () throws GSSException {
        getGSSContext().dispose();
    }
}
