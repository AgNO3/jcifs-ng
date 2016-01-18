package jcifs.smb;


import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.apache.log4j.Logger;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.util.Hexdump;


/**
 * This class implements SmbExtendedAuthenticator interface to provide Kerberos
 * authentication feature.
 *
 * @author Shun
 *
 */
@SuppressWarnings ( "restriction" )
public class Kerb5Authenticator implements SmbCredentials {

    private static final Logger log = Logger.getLogger(Kerb5Authenticator.class);

    private static final String DEFAULT_SERVICE = "cifs";

    private Subject subject = null;
    private String user = null;
    private String realm = null;
    private String service = DEFAULT_SERVICE;
    private int userLifetime = GSSCredential.DEFAULT_LIFETIME;
    private int contextLifetime = GSSContext.DEFAULT_LIFETIME;

    private Key sessionKey;
    private Configuration config;


    /**
     * Contruct a <code>Kerb5Authenticator</code> object with <code>Subject</code>
     * which hold TGT retrieved from KDC. If multiple TGT are contained, the
     * first one will be used to retrieve user principal.
     *
     * @param subject
     *            represents the user who perform Kerberos authentication.
     *            It contains tickets retrieve from KDC.
     */
    public Kerb5Authenticator ( Configuration config, Subject subject ) {
        this.config = config;
        this.subject = subject;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#clone()
     */
    @Override
    public Kerb5Authenticator clone () {
        Kerb5Authenticator kerb5Authenticator = new Kerb5Authenticator(this.config, this.subject);
        kerb5Authenticator.setUser(this.user);
        kerb5Authenticator.setRealm(this.realm);
        kerb5Authenticator.setService(this.service);
        kerb5Authenticator.setLifeTime(this.contextLifetime);
        kerb5Authenticator.setUserLifeTime(this.userLifetime);
        return kerb5Authenticator;
    }


    /**
     * Set the user name which is used to setup <code>GSSContext</code>. If null
     * is set, the default user will be used which is retrieved from the first
     * TGT found in <code>Subject</code> .
     *
     * @param name
     *            the user name used to setup <code>GSSContext</code>
     */
    public void setUser ( String name ) {
        this.user = name;
    }


    /**
     * @param realm
     *            the realm to set
     */
    public void setRealm ( String realm ) {
        this.realm = realm;
    }


    public String getRealm () {
        return this.realm;
    }


    /**
     * @return the sessionKey
     */
    public Key getSessionKey () {
        return this.sessionKey;
    }


    /**
     * Get the <code>Subject</code> object.
     *
     * @return Subject represents the user who perform Kerberos authentication.
     *         It contains the tickets retrieve from KDC.
     */
    public Subject getSubject () {
        return this.subject;
    }


    /**
     * Get the user name which authenticate against to. If the default user
     * is used, Null will be returned.
     *
     * @return user name
     */
    public String getUser () {
        return this.user;
    }


    /**
     * Set the service name which is used to setup <code>GSSContext</code>.
     * Program will use this name to require service ticket from KDC.
     *
     * @param name
     *            the service name used to require service ticket from KDC.
     */
    public void setService ( String name ) {
        this.service = name;
    }


    /**
     * Get the service name.
     *
     * @return the service name used to require service ticket from KDC
     */
    public String getService () {
        return this.service;
    }


    /**
     * Get lifetime of current user.
     *
     * @return the remaining lifetime in seconds. If the default lifetime is
     *         used, this value have no meaning.
     *
     */
    public int getUserLifeTime () {
        return this.userLifetime;
    }


    /**
     * Set lifetime of current user.
     *
     * @param time
     *            the lifetime in seconds
     *
     */
    public void setUserLifeTime ( int time ) {
        this.userLifetime = time;
    }


    /**
     * Get lifetime of this context.
     *
     * @return the remaining lifetime in seconds. If the default lifetime is
     *         used, this value have no meaning.
     */
    public int getLifeTime () {
        return this.contextLifetime;
    }


    /**
     * Set the lifetime for this context.
     *
     * @param time
     *            the lifetime in seconds
     */
    public void setLifeTime ( int time ) {
        this.contextLifetime = time;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbCredentials#isAnonymous()
     */
    @Override
    public boolean isAnonymous () {
        return this.subject == null;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        return "Kerb5Authenticatior[subject=" + ( this.subject != null ? this.subject.getPrincipals() : null ) + ",user=" + this.user + ",realm="
                + this.realm + "]";
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.SessionSetupHandler#sessionSetup(jcifs.smb.SmbSession, jcifs.smb.ServerMessageBlock,
     *      jcifs.smb.ServerMessageBlock)
     */
    @Override
    public void sessionSetup ( final SmbSession session, final ServerMessageBlock andx, final ServerMessageBlock andxResponse ) throws SmbException {
        try {
            Subject.doAs(this.subject, new PrivilegedExceptionAction<Object>() {

                @Override
                public Object run () throws Exception {
                    setup(session, andx, andxResponse);
                    return null;
                }
            });
        }
        catch ( PrivilegedActionException e ) {
            if ( e.getException() instanceof SmbException ) {
                throw (SmbException) e.getException();
            }
            throw new SmbException(e.getMessage(), e.getException());
        }
    }


    void setup ( SmbSession session, ServerMessageBlock andx, ServerMessageBlock andxResponse )
            throws SmbAuthException, SmbException, GeneralSecurityException {
        SpnegoContext context = null;
        try {
            String host = session.getTransport().address.getHostAddress();
            try {
                host = session.getTransport().address.getHostName();
            }
            catch ( Exception e ) {
                log.debug("Failed to resolve host name", e);
            }
            context = createContext(host);

            byte[] token = new byte[0];

            SmbComSessionSetupAndX request = null;
            SmbComSessionSetupAndXResponse response = null;

            while ( !context.isEstablished() ) {
                if ( token != null && log.isDebugEnabled() ) {
                    log.debug("Input token is " + Hexdump.toHexString(token, 0, token.length));
                }
                token = context.initSecContext(token, 0, token != null ? token.length : 0);
                if ( token != null ) {
                    request = new SmbComSessionSetupAndX(session, null/* andx */, token);
                    response = new SmbComSessionSetupAndXResponse(session.getConfig(), andxResponse);
                    setupSessionKey(context, this.subject);

                    if ( session.getTransport().digest == null
                            && ( session.getTransport().server.signaturesRequired || ( session.getTransport().server.signaturesEnabled
                                    && session.getTransport().getTransportContext().getConfig().isSigningPreferred() ) ) ) {
                        if ( this.sessionKey == null ) {
                            throw new SmbAuthException("Kerberos session key not found.");
                        }
                        log.debug("SMB Signatures are enabled");
                        request.digest = new SigningDigest(this.sessionKey.getEncoded());
                    }
                    else {
                        log.debug("SMB Signatures are disabled");
                    }
                    session.getTransport().send(request, response);
                    session.getTransport().digest = request.digest;
                    token = response.blob;
                }
            }

            if ( response == null ) {
                throw new SmbAuthException("No auth response");
            }

            session.setUid(response.uid);
            session.setSessionSetup(true);

        }
        catch (
            GSSException |
            CIFSException e ) {
            throw new SmbAuthException("Kerberos session setup has failed.", e);
        }
        finally {
            if ( context != null ) {
                try {
                    context.dispose();
                }
                catch ( GSSException e ) {
                    log.warn("Failed to dispose context", e);
                }
            }
        }
    }


    /**
     * @param spnego
     * @param subj
     * @throws GSSException
     */
    private void setupSessionKey ( SpnegoContext spnego, Subject subj ) throws GSSException {
        ExtendedGSSContext gss = (ExtendedGSSContext) spnego.getGSSContext();
        this.sessionKey = (Key) gss.inquireSecContext(InquireType.KRB5_GET_SESSION_KEY);
    }


    private SpnegoContext createContext ( String host ) throws GSSException {
        Kerb5Context kerb5Context = new Kerb5Context(host, this.service, this.user, this.userLifetime, this.contextLifetime, this.realm);
        kerb5Context.getGSSContext().requestAnonymity(false);
        kerb5Context.getGSSContext().requestSequenceDet(false);
        kerb5Context.getGSSContext().requestMutualAuth(false);
        kerb5Context.getGSSContext().requestConf(false);
        kerb5Context.getGSSContext().requestInteg(false);
        kerb5Context.getGSSContext().requestReplayDet(false);
        return new SpnegoContext(kerb5Context, getSupportedMechs());
    }


    /**
     * @return
     */
    private static Oid[] getSupportedMechs () throws GSSException {
        Oid[] oids = new Oid[2];
        oids[ 0 ] = new Oid("1.2.840.113554.1.2.2");
        oids[ 1 ] = new Oid("1.2.840.48018.1.2.2");
        return oids;
    }


    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals ( Object other ) {
        // this method is called from SmbSession
        if ( other != null && Kerb5Authenticator.class == other.getClass() )
            return this.getSubject() == ( (Kerb5Authenticator) other ).getSubject();

        return false;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode () {
        return super.hashCode();
    }


    @Override
    public String getUserDomain () {
        String rlm = "";
        if ( this.subject != null ) {
            Set<Principal> pr = this.subject.getPrincipals();
            for ( Iterator<Principal> ite = pr.iterator(); ite.hasNext(); ) {
                try {
                    KerberosPrincipal entry = (KerberosPrincipal) ite.next();
                    rlm = entry.getRealm();
                    break;
                }
                catch ( Exception e ) {
                    continue;
                }
            }
        }
        if ( rlm.isEmpty() ) {
            return this.config.getDefaultDomain();
        }
        return rlm;
    }

}
