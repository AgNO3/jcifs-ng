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
import java.net.MalformedURLException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KeyTab;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbResource;
import jcifs.smb.JAASAuthenticator;
import jcifs.smb.Kerb5Authenticator;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbUnsupportedOperationException;
import sun.security.jgss.krb5.Krb5Util;
import sun.security.krb5.Asn1Exception;
import sun.security.krb5.Credentials;
import sun.security.krb5.EncryptionKey;
import sun.security.krb5.KrbAsReqBuilder;
import sun.security.krb5.KrbException;
import sun.security.krb5.PrincipalName;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( {
    "javadoc", "restriction"
} )
@RunWith ( Parameterized.class )
public class KerberosTest extends BaseCIFSTest {

    /**
     * @param properties
     */
    public KerberosTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Test
    public void testKRB () throws IOException, Asn1Exception, KrbException {
        Subject s = getInitiatorSubject(getTestUser(), getTestUserPassword(), getTestUserDomainRequired());
        CIFSContext ctx = getContext()
                .withCredentials(new Kerb5Authenticator(getContext(), s, getTestUserDomainRequired(), getTestUser(), getTestUserPassword()));
        try ( SmbResource f = new SmbFile(getTestShareURL(), ctx) ) {
            f.exists();
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Using short names", false);
        }
    }


    @Test
    public void testJAAS () throws CIFSException, MalformedURLException {
        CIFSContext ctx = getContext()
                .withCredentials(new JAASAuthenticator(getContext(), getTestUserDomainRequired(), getTestUser(), getTestUserPassword()));
        try ( SmbResource f = new SmbFile(getTestShareURL(), ctx) ) {
            f.exists();
        }
        catch ( SmbUnsupportedOperationException e ) {
            Assume.assumeTrue("Using short names", false);
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
        PrincipalName principalName = new PrincipalName(principal.toString(), PrincipalName.KRB_NT_PRINCIPAL);
        EncryptionKey[] keys = Krb5Util.keysFromJavaxKeyTab(keytab, principalName);

        if ( keys == null || keys.length == 0 ) {
            throw new KrbException("Could not find any keys in keytab for " + principalName); //$NON-NLS-1$
        }

        KrbAsReqBuilder builder = new KrbAsReqBuilder(principalName, keytab);
        Credentials creds = builder.action().getCreds();
        builder.destroy();

        return Krb5Util.credsToTicket(creds);
    }


    public static Subject getInitiatorSubject ( KerberosPrincipal principal, String password ) throws Asn1Exception, KrbException, IOException {
        KerberosTicket ticket = getKerberosTicket(principal, password);
        Set<Object> privCreds = new HashSet<>();
        privCreds.add(ticket);
        return new Subject(false, new HashSet<>(Arrays.asList((Principal) principal)), Collections.EMPTY_SET, privCreds);
    }


    private static KerberosTicket getKerberosTicket ( KerberosPrincipal principal, String password ) throws Asn1Exception, KrbException, IOException {
        PrincipalName principalName;

        principalName = new PrincipalName(principal.getName(), PrincipalName.KRB_NT_PRINCIPAL, principal.getRealm());

        KrbAsReqBuilder builder = new KrbAsReqBuilder(principalName, password != null ? password.toCharArray() : new char[0]);
        Credentials creds = builder.action().getCreds();
        builder.destroy();

        KerberosTicket ticket = Krb5Util.credsToTicket(creds);
        return ticket;
    }


    public static Subject getInitiatorSubject ( String userName, String password, String realm ) throws Asn1Exception, KrbException, IOException {
        String fullPrincipal = String.format("%s@%s", userName, realm); //$NON-NLS-1$
        KerberosPrincipal principal = new KerberosPrincipal(fullPrincipal, KerberosPrincipal.KRB_NT_PRINCIPAL);
        return getInitiatorSubject(principal, password);
    }
}
