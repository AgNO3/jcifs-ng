/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs.tests;


import java.io.IOException;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KeyTab;

import org.ietf.jgss.GSSException;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbResource;
import jcifs.SmbTreeHandle;
import jcifs.smb.JAASAuthenticator;
import jcifs.smb.Kerb5Authenticator;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbSessionInternal;
import jcifs.smb.SmbTreeHandleInternal;
import jcifs.smb.SmbUnsupportedOperationException;
import sun.security.jgss.krb5.Krb5Util;
import sun.security.krb5.Asn1Exception;
import sun.security.krb5.Credentials;
import sun.security.krb5.EncryptionKey;
import sun.security.krb5.KrbAsReqBuilder;
import sun.security.krb5.KrbException;
import sun.security.krb5.PrincipalName;
import sun.security.krb5.RealmException;
import sun.security.krb5.internal.KerberosTime;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( {
    "javadoc", "restriction"
} )
@RunWith ( Parameterized.class )
public class KerberosTest extends BaseCIFSTest {

    private static final Logger log = LoggerFactory.getLogger(KerberosTest.class);


    /**
     * @param properties
     */
    public KerberosTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "smb2", "smb30", "smb31", "forceSpnegoIntegrity");
    }


    @Before
    public void setup () {
        Assume.assumeTrue("Skip kerberos auth", getProperties().get("test.skip.kerberos") == null);
    }


    @Test
    public void testKRB () throws Exception {
        Subject s = getInitiatorSubject(getTestUser(), getTestUserPassword(), getTestUserDomainRequired(), null);
        CIFSContext ctx = getContext().withCredentials(new Kerb5Authenticator(s, getTestUserDomainRequired(), getTestUser(), getTestUserPassword()));
        try ( SmbResource f = new SmbFile(getTestShareURL(), ctx) ) {
            f.exists();
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Using short names", false);
        }
    }


    @Test
    public void testJAAS () throws CIFSException, MalformedURLException {
        CIFSContext ctx = getContext().withCredentials(new JAASAuthenticator(getTestUserDomainRequired(), getTestUser(), getTestUserPassword()));
        try ( SmbResource f = new SmbFile(getTestShareURL(), ctx) ) {
            f.exists();
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Using short names", false);
        }
    }


    @Test
    public void testFallback () throws Exception {
        Subject s = getInitiatorSubject(getTestUser(), getTestUserPassword(), getTestUserDomainRequired(), null);
        Kerb5Authenticator auth = new Kerb5Authenticator(s, getTestUserDomainRequired(), getTestUser(), getTestUserPassword());
        auth.setForceFallback(true);
        CIFSContext ctx = getContext().withCredentials(auth);
        try ( SmbResource f = new SmbFile(getTestShareURL(), ctx) ) {
            f.exists();
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Using short names", false);
        }
    }


    @Test
    public void testReauthenticate () throws Exception {
        Subject s = getInitiatorSubject(getTestUser(), getTestUserPassword(), getTestUserDomainRequired(), null);
        Kerb5Authenticator creds = new RefreshableKerb5Authenticator(s, getTestUserDomainRequired(), getTestUser(), getTestUserPassword());
        CIFSContext ctx = getContext().withCredentials(creds);
        try ( SmbFile f = new SmbFile(getTestShareURL(), ctx);
              SmbTreeHandleInternal th = (SmbTreeHandleInternal) f.getTreeHandle();
              SmbSessionInternal session = (SmbSessionInternal) th.getSession() ) {
            Assume.assumeTrue("Not SMB2", th.isSMB2());
            f.exists();
            session.reauthenticate();
            f.exists();
        }
    }


    @Test
    public void testSessionExpiration () throws Exception {
        long start = System.currentTimeMillis() / 1000 * 1000;
        // this is not too great as it depends on timing/clockskew
        // first we need to obtain a ticket, therefor need valid credentials
        // then we need to wait until the ticket is expired
        int wait = 10 * 1000;
        long princExp = start + ( wait / 2 );
        Subject s = getInitiatorSubject(getTestUser(), getTestUserPassword(), getTestUserDomainRequired(), princExp);
        Kerb5Authenticator creds = new RefreshableKerb5Authenticator(s, getTestUserDomainRequired(), getTestUser(), getTestUserPassword());
        CIFSContext ctx = getContext().withCredentials(creds);
        try ( SmbFile f = new SmbFile(getTestShareURL(), ctx) ) {
            try ( SmbTreeHandle th = f.getTreeHandle() ) {
                Assume.assumeTrue("Not SMB2", th.isSMB2());
            }

            f.exists();
            Thread.sleep(wait);

            try ( SmbResource r = f.resolve("test") ) {
                r.exists();
            }
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Using short names", false);
        }
        catch ( SmbException e ) {
            if ( ! ( e.getCause() instanceof GSSException ) ) {
                throw e;
            }
            log.error("Kerberos problem", e);
            Assume.assumeTrue("Kerberos problem, clockskew?", false);
        }
    }


    public static Subject getInitiatorSubject ( KeyTab keytab, final KerberosPrincipal principal ) throws Asn1Exception, KrbException, IOException {
        KerberosTicket ticket = getKerberosTicket(keytab, principal);
        Set<Object> privCreds = new HashSet<>();
        privCreds.add(ticket);
        return new Subject(false, new HashSet<>(Arrays.asList((Principal) principal)), Collections.EMPTY_SET, privCreds);
    }


    private static KerberosTicket getKerberosTicket ( KeyTab keytab, final KerberosPrincipal principal )
            throws Asn1Exception, KrbException, IOException {
        PrincipalName principalName = convertPrincipal(principal);
        EncryptionKey[] keys = Krb5Util.keysFromJavaxKeyTab(keytab, principalName);

        if ( keys == null || keys.length == 0 ) {
            throw new KrbException("Could not find any keys in keytab for " + principalName); //$NON-NLS-1$
        }

        KrbAsReqBuilder builder = new KrbAsReqBuilder(principalName, keytab);
        Credentials creds = builder.action().getCreds();
        builder.destroy();

        return Krb5Util.credsToTicket(creds);
    }


    public static Subject getInitiatorSubject ( KerberosPrincipal principal, String password, Long expire ) throws Exception {
        KerberosTicket ticket = getKerberosTicket(principal, password, expire);
        Set<Object> privCreds = new HashSet<>();
        privCreds.add(ticket);
        return new Subject(false, new HashSet<>(Arrays.asList((Principal) principal)), Collections.EMPTY_SET, privCreds);
    }


    private static KerberosTicket getKerberosTicket ( KerberosPrincipal principal, String password, Long expire ) throws Exception {
        PrincipalName principalName = convertPrincipal(principal);
        KrbAsReqBuilder builder = new KrbAsReqBuilder(principalName, password != null ? password.toCharArray() : new char[0]);

        if ( expire != null ) {
            System.out.println("Request expires " + expire);
            KerberosTime till = new KerberosTime(expire);
            Field tillF = builder.getClass().getDeclaredField("till");
            tillF.setAccessible(true);
            tillF.set(builder, till);
        }

        Credentials creds = builder.action().getCreds();
        builder.destroy();

        KerberosTicket ticket = Krb5Util.credsToTicket(creds);
        System.out.println("Ends " + ticket.getEndTime().getTime());
        return ticket;
    }


    /**
     * @param principal
     * @return
     * @throws RealmException
     */
    protected static PrincipalName convertPrincipal ( KerberosPrincipal principal ) throws RealmException {
        PrincipalName principalName = new PrincipalName(
            principal.getName() + PrincipalName.NAME_REALM_SEPARATOR + principal.getRealm(),
            PrincipalName.KRB_NT_PRINCIPAL);
        return principalName;
    }


    public static Subject getInitiatorSubject ( String userName, String password, String realm, Long expire ) throws Exception {
        KerberosPrincipal principal = new KerberosPrincipal(String.format("%s@%s", userName, realm), KerberosPrincipal.KRB_NT_PRINCIPAL);
        return getInitiatorSubject(principal, password, expire);
    }

    public final class RefreshableKerb5Authenticator extends Kerb5Authenticator {

        /**
         * 
         */
        private static final long serialVersionUID = -4979600496889213143L;


        public RefreshableKerb5Authenticator ( Subject subject, String domain, String username, String password ) {
            super(subject, domain, username, password);
        }


        @Override
        public void refresh () throws CIFSException {
            try {
                System.out.println("Refreshing");
                setSubject(getInitiatorSubject(getTestUser(), getTestUserPassword(), getTestUserDomainRequired(), null));
                System.out.println("Refreshed");
            }
            catch ( Exception e ) {
                throw new CIFSException("Failed to refresh credentials", e);
            }
        }


        @Override
        public Kerb5Authenticator clone () {
            Kerb5Authenticator auth = new RefreshableKerb5Authenticator(getSubject(), getUserDomain(), getUser(), getPassword());
            cloneInternal(auth, this);
            return auth;
        }
    }
}
