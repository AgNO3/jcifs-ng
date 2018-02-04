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
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.spnego.NegTokenInit;


/**
 * Base kerberos authenticator
 * 
 * Uses a subject that contains kerberos credentials for use in GSSAPI context establishment.
 * 
 * Be advised that short/NetBIOS name usage is not supported with this authenticator. Always specify full FQDNs.
 * This can be a problem if using DFS in it's default configuration as they still return referrals in short form.
 * See <a href="https://support.microsoft.com/en-us/kb/244380">KB-244380</a> for compatible server configuration.
 * See {@link jcifs.Configuration#isDfsConvertToFQDN()} for a workaround.
 */
public class Kerb5Authenticator extends NtlmPasswordAuthenticator {

    private static final long serialVersionUID = 1999400043787454432L;
    private static final Logger log = LoggerFactory.getLogger(Kerb5Authenticator.class);
    private static final String DEFAULT_SERVICE = "cifs";

    private static final Set<ASN1ObjectIdentifier> PREFERRED_MECHS = new HashSet<>();

    private Subject subject = null;
    private String user = null;
    private String realm = null;
    private String service = DEFAULT_SERVICE;
    private int userLifetime = GSSCredential.DEFAULT_LIFETIME;
    private int contextLifetime = GSSContext.DEFAULT_LIFETIME;
    private boolean canFallback = false;
    private boolean forceFallback;

    static {
        PREFERRED_MECHS.add(new ASN1ObjectIdentifier("1.2.840.113554.1.2.2"));
        PREFERRED_MECHS.add(new ASN1ObjectIdentifier("1.2.840.48018.1.2.2"));
    }


    /**
     * Construct a <code>Kerb5Authenticator</code> object with <code>Subject</code>
     * which hold TGT retrieved from KDC. If multiple TGT are contained, the
     * first one will be used to retrieve user principal.
     * 
     * @param subject
     *            represents the user who perform Kerberos authentication.
     *            It contains tickets retrieve from KDC.
     */
    public Kerb5Authenticator ( Subject subject ) {
        this.subject = subject;
    }


    /**
     * Construct a <code>Kerb5Authenticator</code> object with <code>Subject</code> and
     * potential NTLM fallback (if the server does not support kerberos).
     * 
     * @param subject
     *            represents the user who perform Kerberos authentication. Should at least contain a TGT for the user.
     * @param domain
     *            domain for NTLM fallback
     * @param username
     *            user for NTLM fallback
     * @param password
     *            password for NTLM fallback
     */
    public Kerb5Authenticator ( Subject subject, String domain, String username, String password ) {
        super(domain, username, password);
        this.canFallback = true;
        this.subject = subject;
    }


    /**
     * Testing only: force fallback to NTLM
     * 
     * @param forceFallback
     *            the forceFallback to set
     */
    public void setForceFallback ( boolean forceFallback ) {
        this.forceFallback = forceFallback;
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.NtlmPasswordAuthenticator#createContext(jcifs.CIFSContext, java.lang.String, java.lang.String,
     *      byte[], boolean)
     */
    @Override
    public SSPContext createContext ( CIFSContext tc, String targetDomain, String host, byte[] initialToken, boolean doSigning ) throws SmbException {
        if ( host.indexOf('.') < 0 && host.toUpperCase(Locale.ROOT).equals(host) ) {
            // this is not too good, probably should better pass the address and check that it is a netbios one.
            // While we could look up the domain controller/KDC we cannot really make the java kerberos implementation
            // use a KDC of our choice.
            // A potential workaround would be to try to get the server FQDN by reverse lookup, but this might have
            // security implications and also is not how Microsoft does it.
            throw new SmbUnsupportedOperationException("Cannot use netbios/short names with kerberos authentication, have " + host);
        }
        try {
            NegTokenInit tok = new NegTokenInit(initialToken);
            if ( log.isDebugEnabled() ) {
                log.debug("Have initial token " + tok);
            }
            if ( tok.getMechanisms() != null ) {
                Set<ASN1ObjectIdentifier> mechs = new HashSet<>(Arrays.asList(tok.getMechanisms()));
                boolean foundKerberos = false;
                for ( ASN1ObjectIdentifier mech : Kerb5Context.SUPPORTED_MECHS ) {
                    foundKerberos |= mechs.contains(mech);
                }
                if ( ( !foundKerberos || this.forceFallback ) && this.canFallback && tc.getConfig().isAllowNTLMFallback() ) {
                    log.debug("Falling back to NTLM authentication");
                    return super.createContext(tc, targetDomain, host, initialToken, doSigning);
                }
                else if ( !foundKerberos ) {
                    throw new SmbUnsupportedOperationException("Server does not support kerberos authentication");
                }
            }
        }
        catch ( SmbException e ) {
            throw e;
        }
        catch ( IOException e1 ) {
            log.debug("Ignoring invalid initial token", e1);
        }

        try {
            return createContext(tc, targetDomain, host);
        }
        catch ( GSSException e ) {
            throw new SmbException("Context setup failed", e);
        }
    }


    /**
     * @param subject
     *            the subject to set
     */
    protected void setSubject ( Subject subject ) {
        this.subject = subject;
    }


    @Override
    public void refresh () throws CIFSException {
        // custom Kerb5Authenticators need to override this method for support
        throw new SmbUnsupportedOperationException("Refreshing credentials is not supported by this authenticator");
    }


    @Override
    public Kerb5Authenticator clone () {
        Kerb5Authenticator auth = new Kerb5Authenticator(getSubject());
        cloneInternal(auth, this);
        return auth;
    }


    /**
     * Clone the context
     * 
     * @param to
     * @param from
     */
    public static void cloneInternal ( Kerb5Authenticator to, Kerb5Authenticator from ) {
        NtlmPasswordAuthenticator.cloneInternal(to, from);
        to.setUser(from.getUser());
        to.setRealm(from.getRealm());
        to.setService(from.getService());
        to.setLifeTime(from.getLifeTime());
        to.setUserLifeTime(from.getUserLifeTime());

        to.canFallback = from.canFallback;
        to.forceFallback = from.forceFallback;
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


    /**
     * 
     * @return the kerberos realm
     */
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
     * @see jcifs.smb.CredentialsInternal#isAnonymous()
     */
    @Override
    public boolean isAnonymous () {
        return this.getSubject() == null && super.isAnonymous();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.NtlmPasswordAuthenticator#isPreferredMech(org.bouncycastle.asn1.ASN1ObjectIdentifier)
     */
    @Override
    public boolean isPreferredMech ( ASN1ObjectIdentifier mechanism ) {
        if ( isAnonymous() ) {
            return super.isPreferredMech(mechanism);
        }
        return PREFERRED_MECHS.contains(mechanism);
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


    private SpnegoContext createContext ( CIFSContext tc, String targetDomain, String host ) throws GSSException {
        return new SpnegoContext(
            tc.getConfig(),
            new Kerb5Context(
                host,
                this.service,
                this.user,
                this.userLifetime,
                this.contextLifetime,
                targetDomain != null ? targetDomain.toUpperCase(Locale.ROOT) : null));
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.NtlmPasswordAuthenticator#equals(java.lang.Object)
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
