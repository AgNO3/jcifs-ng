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


import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Key;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.spnego.NegTokenInit;


/**
 * This class used to provide Kerberos feature when setup GSSContext.
 * 
 * @author Shun
 */
class Kerb5Context implements SSPContext {

    private static final Logger log = LoggerFactory.getLogger(Kerb5Context.class);

    private static final ASN1ObjectIdentifier KRB5_MECH_OID;
    private static final ASN1ObjectIdentifier KRB5_MS_MECH_OID;
    static final ASN1ObjectIdentifier[] SUPPORTED_MECHS;
    private static final Oid JGSS_KRB5_NAME_OID;
    private static final Oid JGSS_KRB5_MECH_OID;

    static {
        KRB5_MECH_OID = new ASN1ObjectIdentifier("1.2.840.113554.1.2.2");
        KRB5_MS_MECH_OID = new ASN1ObjectIdentifier("1.2.840.48018.1.2.2");
        SUPPORTED_MECHS = new ASN1ObjectIdentifier[] {
            KRB5_MECH_OID, KRB5_MS_MECH_OID
        };

        Oid krbNameOid = null;
        Oid krbMechOid = null;
        try {
            krbNameOid = new Oid("1.2.840.113554.1.2.2.1");
            krbMechOid = new Oid("1.2.840.113554.1.2.2");
        }
        catch ( Exception e ) {
            log.error("Failed to initialize kerberos OIDs", e);
        }

        JGSS_KRB5_NAME_OID = krbNameOid;
        JGSS_KRB5_MECH_OID = krbMechOid;
    }

    private final GSSContext gssContext;
    private final GSSName clientName;
    private final GSSName serviceName;


    Kerb5Context ( String host, String service, String name, int userLifetime, int contextLifetime, String realm ) throws GSSException {
        GSSManager manager = GSSManager.getInstance();
        GSSCredential clientCreds = null;
        Oid mechOid = JGSS_KRB5_MECH_OID;
        if ( realm != null ) {
            this.serviceName = manager.createName(service + "/" + host + "@" + realm, JGSS_KRB5_NAME_OID, mechOid);
        }
        else {
            this.serviceName = manager.createName(service + "@" + host, GSSName.NT_HOSTBASED_SERVICE, mechOid);
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Service name is " + this.serviceName);
        }

        if ( name != null ) {
            this.clientName = manager.createName(name, GSSName.NT_USER_NAME, mechOid);
            clientCreds = manager.createCredential(this.clientName, userLifetime, mechOid, GSSCredential.INITIATE_ONLY);
        }
        else {
            this.clientName = null;
        }

        this.gssContext = manager.createContext(this.serviceName, mechOid, clientCreds, contextLifetime);

        this.gssContext.requestAnonymity(false);
        this.gssContext.requestSequenceDet(false);
        this.gssContext.requestConf(false);
        this.gssContext.requestInteg(false);
        this.gssContext.requestReplayDet(false);

        // per spec these should be set
        this.gssContext.requestMutualAuth(true);
        this.gssContext.requestCredDeleg(true);
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#isSupported(org.bouncycastle.asn1.ASN1ObjectIdentifier)
     */
    @Override
    public boolean isSupported ( ASN1ObjectIdentifier mechanism ) {
        return KRB5_MECH_OID.equals(mechanism) || KRB5_MS_MECH_OID.equals(mechanism);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#isPreferredMech(org.bouncycastle.asn1.ASN1ObjectIdentifier)
     */
    @Override
    public boolean isPreferredMech ( ASN1ObjectIdentifier mechanism ) {
        return isSupported(mechanism);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#getSupportedMechs()
     */
    @Override
    public ASN1ObjectIdentifier[] getSupportedMechs () {
        return SUPPORTED_MECHS;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#getFlags()
     */
    @Override
    public int getFlags () {
        int contextFlags = 0;
        if ( this.gssContext.getCredDelegState() ) {
            contextFlags |= NegTokenInit.DELEGATION;
        }
        if ( this.gssContext.getMutualAuthState() ) {
            contextFlags |= NegTokenInit.MUTUAL_AUTHENTICATION;
        }
        if ( this.gssContext.getReplayDetState() ) {
            contextFlags |= NegTokenInit.REPLAY_DETECTION;
        }
        if ( this.gssContext.getSequenceDetState() ) {
            contextFlags |= NegTokenInit.SEQUENCE_CHECKING;
        }
        if ( this.gssContext.getAnonymityState() ) {
            contextFlags |= NegTokenInit.ANONYMITY;
        }
        if ( this.gssContext.getConfState() ) {
            contextFlags |= NegTokenInit.CONFIDENTIALITY;
        }
        if ( this.gssContext.getIntegState() ) {
            contextFlags |= NegTokenInit.INTEGRITY;
        }
        return contextFlags;
    }


    @Override
    public boolean isEstablished () {
        return this.gssContext != null && this.gssContext.isEstablished();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#supportsIntegrity()
     */
    @Override
    public boolean supportsIntegrity () {
        return true;
    }


    /**
     * {@inheritDoc}
     * 
     * @throws CIFSException
     *
     * @see jcifs.smb.SSPContext#calculateMIC(byte[])
     */
    @Override
    public byte[] calculateMIC ( byte[] data ) throws CIFSException {
        try {
            return this.gssContext.getMIC(data, 0, data.length, new MessageProp(false));
        }
        catch ( GSSException e ) {
            throw new CIFSException("Failed to calculate MIC", e);
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#verifyMIC(byte[], byte[])
     */
    @Override
    public void verifyMIC ( byte[] data, byte[] mic ) throws CIFSException {
        try {
            this.gssContext.verifyMIC(mic, 0, mic.length, data, 0, data.length, new MessageProp(false));
        }
        catch ( GSSException e ) {
            throw new CIFSException("Failed to verify MIC", e);
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#isMICAvailable()
     */
    @Override
    public boolean isMICAvailable () {
        return this.gssContext.getIntegState();
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
    public byte[] getSigningKey () throws SmbException {
        /*
         * The kerberos session key is not accessible via the JGSS API. IBM and
         * Oracle both implement a similar API to make an ExtendedGSSContext
         * available. That API is accessed via reflection to make this independent
         * of the runtime JRE
         */
        if ( EXT_GSS_CONTEXT_CLASS == null || INQUIRE_SEC_CONTEXT == null || INQUIRE_TYPE_SESSION_KEY == null ) {
            throw new SmbException("ExtendedGSSContext support not available from JRE");
        }
        else if ( EXT_GSS_CONTEXT_CLASS.isAssignableFrom(this.gssContext.getClass()) ) {
            try {
                Key k = (Key) INQUIRE_SEC_CONTEXT.invoke(this.gssContext, new Object[] {
                    INQUIRE_TYPE_SESSION_KEY
                });
                return k.getEncoded();
            }
            catch (
                IllegalAccessException |
                IllegalArgumentException |
                InvocationTargetException ex ) {
                throw new SmbException("Failed to query Kerberos session key from ExtendedGSSContext", ex);
            }
        }
        throw new SmbException("ExtendedGSSContext is not implemented by GSSContext");
    }


    @Override
    public byte[] initSecContext ( byte[] token, int off, int len ) throws SmbException {
        try {
            return this.gssContext.initSecContext(token, off, len);
        }
        catch ( GSSException e ) {
            throw new SmbAuthException("GSSAPI mechanism failed", e);
        }
    }


    Key searchSessionKey ( Subject subject ) throws GSSException {
        MIEName src = new MIEName(this.gssContext.getSrcName().export());
        MIEName targ = new MIEName(this.gssContext.getTargName().export());

        ASN1ObjectIdentifier mech = ASN1ObjectIdentifier.getInstance(this.gssContext.getMech().getDER());
        for ( KerberosTicket ticket : subject.getPrivateCredentials(KerberosTicket.class) ) {
            MIEName client = new MIEName(mech, ticket.getClient().getName());
            MIEName server = new MIEName(mech, ticket.getServer().getName());
            if ( src.equals(client) && targ.equals(server) ) {
                return ticket.getSessionKey();
            }
        }
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        if ( this.gssContext == null || !this.gssContext.isEstablished() ) {
            return String.format("KERB5[src=%s,targ=%s]", this.clientName, this.serviceName);
        }
        try {
            return String
                    .format("KERB5[src=%s,targ=%s,mech=%s]", this.gssContext.getSrcName(), this.gssContext.getTargName(), this.gssContext.getMech());
        }
        catch ( GSSException e ) {
            log.debug("Failed to get info", e);
            return super.toString();
        }
    }


    @Override
    public void dispose () throws SmbException {
        if ( this.gssContext != null ) {
            try {
                this.gssContext.dispose();
            }
            catch ( GSSException e ) {
                throw new SmbException("Context disposal failed", e);
            }
        }
    }

    /*
     * Prepare reflective access to ExtendedGSSContext. The reflective access
     * abstracts the access so far, that Oracle JDK, Open JDK and IBM JDK are
     * supported.
     * 
     * At the time of the first implementation only a test on Oracle JDK was
     * done.
     */

    private static final String OPENJDK_JGSS_INQUIRE_TYPE_CLASS = "com.sun.security.jgss.InquireType";
    private static final String OPENJDK_JGSS_EXT_GSSCTX_CLASS = "com.sun.security.jgss.ExtendedGSSContext";

    private static final String IBM_JGSS_INQUIRE_TYPE_CLASS = "com.ibm.security.jgss.InquireType";
    private static final String IBM_JGSS_EXT_GSSCTX_CLASS = "com.ibm.security.jgss.ExtendedGSSContext";

    private static final Class<?> EXT_GSS_CONTEXT_CLASS;
    private static final Method INQUIRE_SEC_CONTEXT;
    private static final Object INQUIRE_TYPE_SESSION_KEY;

    static {
        Class<?> extendedGSSContextClassPrep = null;
        Method inquireSecContextPrep = null;
        Object inquireTypeSessionKeyPrep = null;

        try {
            extendedGSSContextClassPrep = Class.forName(OPENJDK_JGSS_EXT_GSSCTX_CLASS);
            Class<?> inquireTypeClass = Class.forName(OPENJDK_JGSS_INQUIRE_TYPE_CLASS);
            inquireTypeSessionKeyPrep = getSessionKeyInquireType(inquireTypeClass);
            inquireSecContextPrep = extendedGSSContextClassPrep.getMethod("inquireSecContext", inquireTypeClass);
        }
        catch (
            ClassNotFoundException |
            NoSuchMethodException |
            RuntimeException ex ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Failed to initalize ExtendedGSSContext initializdation for OracleJDK / OpenJDK", ex);
            }
        }

        if ( extendedGSSContextClassPrep == null || inquireSecContextPrep == null || inquireTypeSessionKeyPrep == null ) {
            try {
                extendedGSSContextClassPrep = Class.forName(IBM_JGSS_EXT_GSSCTX_CLASS);
                Class<?> inquireTypeClass = Class.forName(IBM_JGSS_INQUIRE_TYPE_CLASS);
                inquireTypeSessionKeyPrep = getSessionKeyInquireType(inquireTypeClass);
                inquireSecContextPrep = extendedGSSContextClassPrep.getMethod("inquireSecContext", inquireTypeClass);
            }
            catch (
                ClassNotFoundException |
                NoSuchMethodException |
                RuntimeException ex ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Failed to initalize ExtendedGSSContext initializdation for IBM JDK", ex);
                }
            }
        }
        EXT_GSS_CONTEXT_CLASS = extendedGSSContextClassPrep;
        INQUIRE_SEC_CONTEXT = inquireSecContextPrep;
        INQUIRE_TYPE_SESSION_KEY = inquireTypeSessionKeyPrep;

        if ( EXT_GSS_CONTEXT_CLASS != null && INQUIRE_SEC_CONTEXT != null && INQUIRE_TYPE_SESSION_KEY != null ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Found ExtendedGSSContext implementation: " + EXT_GSS_CONTEXT_CLASS.getName());
            }
        }
    }


    @SuppressWarnings ( "unchecked" )
    private static <T extends Enum<T>> Object getSessionKeyInquireType ( Class<?> inquireTypeClass ) {
        return Enum.valueOf((Class<T>) inquireTypeClass, "KRB5_GET_SESSION_KEY");
    }
}
