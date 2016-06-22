package jcifs.smb;


import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.apache.log4j.Logger;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

import jcifs.CIFSContext;
import jcifs.spnego.NegTokenInit;


/**
 * 
 * @author Shun
 *
 */
public class Kerb5Authenticator extends NtlmPasswordAuthentication {

    /**
     * 
     */

    private static final long serialVersionUID = 1999400043787454432L;
    private static final Logger log = Logger.getLogger(Kerb5Authenticator.class);
    private static final String DEFAULT_SERVICE = "cifs";

    private Subject subject = null;
    private String user = null;
    private String realm = null;
    private String service = DEFAULT_SERVICE;
    private int userLifetime = GSSCredential.DEFAULT_LIFETIME;
    private int contextLifetime = GSSContext.DEFAULT_LIFETIME;


    /**
     * Contruct a <code>Kerb5Authenticator</code> object with <code>Subject</code>
     * which hold TGT retrieved from KDC. If multiple TGT are contained, the
     * first one will be used to retrieve user principal.
     *
     * @param subject
     *            represents the user who perform Kerberos authentication.
     *            It contains tickets retrieve from KDC.
     */
    public Kerb5Authenticator ( CIFSContext tc, Subject subject ) {
        super(tc);
        this.subject = subject;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbCredentials#createContext(jcifs.CIFSContext)
     */
    @Override
    public SSPContext createContext ( CIFSContext transportContext, String host, byte[] initialToken, boolean doSigning ) throws SmbException {
        try {
            NegTokenInit tok = new NegTokenInit(initialToken);
            if ( log.isDebugEnabled() ) {
                log.debug("Have initial token " + tok);
            }
            if ( tok.getMechanisms() != null ) {
                Set<Oid> mechs = new HashSet<>(Arrays.asList(tok.getMechanisms()));
                boolean foundKerberos = false;
                for ( Oid mech : Kerb5Context.SUPPORTED_MECHS ) {
                    foundKerberos |= mechs.contains(mech);
                }
                if ( !foundKerberos ) {
                    log.debug("Falling back to NTLM authentication");
                    return super.createContext(transportContext, host, initialToken, doSigning);
                }
            }
        }
        catch ( IOException e1 ) {
            log.debug("Ignoring invalid initial token", e1);
        }

        try {
            return createContext(host);
        }
        catch ( GSSException e ) {
            throw new SmbException("Context setup failed", e);
        }
    }


    @Override
    public Kerb5Authenticator clone () {
        Kerb5Authenticator auth = new Kerb5Authenticator(this.getContext(), this.getSubject());
        cloneInternal(auth, this);
        return auth;
    }


    public static void cloneInternal ( Kerb5Authenticator to, Kerb5Authenticator from ) {
        NtlmPasswordAuthentication.cloneInternal(to, from);
        to.setUser(from.getUser());
        to.setRealm(from.getRealm());
        to.setService(from.getService());
        to.setLifeTime(from.getLifeTime());
        to.setUserLifeTime(from.getUserLifeTime());
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
     * Get the <code>Subject</code> object.
     *
     * @return Subject represents the user who perform Kerberos authentication.
     *         It contains the tickets retrieve from KDC.
     */
    @Override
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
        return this.getSubject() == null && super.isAnonymous();
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        return "Kerb5Authenticatior[subject=" + ( this.getSubject() != null ? this.getSubject().getPrincipals() : null ) + ",user=" + this.user
                + ",realm=" + this.realm + "]";
    }


    private SpnegoContext createContext ( String host ) throws GSSException {
        return new SpnegoContext(new Kerb5Context(host, this.service, this.user, this.userLifetime, this.contextLifetime, this.realm));
    }


    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals ( Object other ) {
        // this method is called from SmbSession
        if ( other != null && other instanceof Kerb5Authenticator )
            return Objects.equals(this.getSubject(), ( (Kerb5Authenticator) other ).getSubject());

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
        if ( this.realm == null && this.getSubject() != null ) {
            Set<Principal> pr = this.getSubject().getPrincipals();
            for ( Iterator<Principal> ite = pr.iterator(); ite.hasNext(); ) {
                try {
                    KerberosPrincipal entry = (KerberosPrincipal) ite.next();
                    return entry.getRealm();
                }
                catch ( Exception e ) {
                    continue;
                }
            }
        }

        if ( this.realm != null ) {
            return this.realm;
        }

        return super.getUserDomain();
    }

}
