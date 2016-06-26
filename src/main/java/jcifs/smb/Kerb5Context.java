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


import java.security.Key;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;

import org.apache.log4j.Logger;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;

import jcifs.spnego.NegTokenInit;


/**
 * This class used to provide Kerberos feature when setup GSSContext.
 * 
 * @author Shun
 */
@SuppressWarnings ( "restriction" )
class Kerb5Context implements SSPContext {

    private static final Logger log = Logger.getLogger(Kerb5Context.class);

    private static Oid KRB5_MECH_OID;
    private static Oid KRB5_MS_MECH_OID;
    private static Oid KRB5_NAME_OID;

    static Oid[] SUPPORTED_MECHS;


    static {
        try {
            KRB5_MECH_OID = new Oid("1.2.840.113554.1.2.2");
            KRB5_MS_MECH_OID = new Oid("1.2.840.48018.1.2.2");
            KRB5_NAME_OID = new Oid("1.2.840.113554.1.2.2.1");
            SUPPORTED_MECHS = new Oid[] {
                KRB5_MECH_OID, KRB5_MS_MECH_OID
            };
        }
        catch ( GSSException e ) {
            log.error("Failed to initialize kerberos OIDs");
        }
    }

    private GSSContext gssContext;

    private GSSName clientName;

    private GSSName serviceName;


    Kerb5Context ( String host, String service, String name, int userLifetime, int contextLifetime, String realm ) throws GSSException {
        GSSManager manager = GSSManager.getInstance();
        GSSCredential clientCreds = null;
        if ( realm != null ) {
            this.serviceName = manager.createName(service + "/" + host + "@" + realm, KRB5_NAME_OID, KRB5_MECH_OID);
        }
        else {
            this.serviceName = manager.createName(service + "@" + host, GSSName.NT_HOSTBASED_SERVICE, KRB5_MECH_OID);
        }

        if ( name != null ) {
            this.clientName = manager.createName(name, GSSName.NT_USER_NAME, KRB5_MECH_OID);
            clientCreds = manager.createCredential(this.clientName, userLifetime, KRB5_MECH_OID, GSSCredential.INITIATE_ONLY);
        }
        this.gssContext = manager.createContext(this.serviceName, KRB5_MECH_OID, clientCreds, contextLifetime);

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
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#isSupported(org.ietf.jgss.Oid)
     */
    @Override
    public boolean isSupported ( Oid mechanism ) {
        return KRB5_MECH_OID.equals(mechanism) || KRB5_MS_MECH_OID.equals(mechanism);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#getSupportedMechs()
     */
    @Override
    public Oid[] getSupportedMechs () {
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
        ExtendedGSSContext gss = (ExtendedGSSContext) this.gssContext;
        try {
            Key k = (Key) gss.inquireSecContext(InquireType.KRB5_GET_SESSION_KEY);
            return k.getEncoded();
        }
        catch ( GSSException e ) {
            throw new SmbException("Failed to get session key", e);
        }

    }


    @Override
    public byte[] initSecContext ( byte[] token, int off, int len ) throws SmbException {
        try {
            return this.gssContext.initSecContext(token, off, len);
        }
        catch ( GSSException e ) {
            throw new SmbException("GSSAPI mechanism failed", e);
        }
    }


    Key searchSessionKey ( Subject subject ) throws GSSException {
        MIEName src = new MIEName(this.gssContext.getSrcName().export());
        MIEName targ = new MIEName(this.gssContext.getTargName().export());

        for ( KerberosTicket ticket : subject.getPrivateCredentials(KerberosTicket.class) ) {
            MIEName client = new MIEName(this.gssContext.getMech(), ticket.getClient().getName());
            MIEName server = new MIEName(this.gssContext.getMech(), ticket.getServer().getName());
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
}
