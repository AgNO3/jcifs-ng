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
package jcifs.pac.kerberos;


import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;


@SuppressWarnings ( "javadoc" )
public class KerberosCredentials {

    private Subject subject;


    public KerberosCredentials () throws LoginException {
        this(System.getProperty("jaaslounge.sso.jaas.config"));
    }


    public KerberosCredentials ( String loginContextName ) throws LoginException {
        LoginContext lc = new LoginContext(loginContextName);
        lc.login();
        this.subject = lc.getSubject();
    }


    public KerberosKey[] getKeys () {
        List<Key> serverKeys = new ArrayList<>();

        Set<Object> serverPrivateCredentials = this.subject.getPrivateCredentials();
        for ( Object credential : serverPrivateCredentials )
            if ( credential instanceof KerberosKey )
                serverKeys.add((KerberosKey) credential);

        return serverKeys.toArray(new KerberosKey[0]);
    }


    public KerberosKey getKey ( int keyType ) {
        KerberosKey serverKey = null;

        Set<Object> serverPrivateCredentials = this.subject.getPrivateCredentials();
        for ( Object credential : serverPrivateCredentials )
            if ( credential instanceof KerberosKey )
                if ( ( (KerberosKey) credential ).getKeyType() == keyType )
                    serverKey = (KerberosKey) credential;

        return serverKey;
    }


    public Subject getSubject () {
        return this.subject;
    }

}
