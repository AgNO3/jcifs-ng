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

import jcifs.pac.PACDecodingException;


@SuppressWarnings ( "javadoc" )
public abstract class KerberosAuthData {

    public static List<KerberosAuthData> parse ( int authType, byte[] token, Key key ) throws PACDecodingException {

        List<KerberosAuthData> authorizations = new ArrayList<>();

        switch ( authType ) {
        case KerberosConstants.AUTH_DATA_RELEVANT:
            authorizations = new KerberosRelevantAuthData(token, key).getAuthorizations();
            break;
        case KerberosConstants.AUTH_DATA_PAC:
            authorizations.add(new KerberosPacAuthData(token, key));
            break;
        default:
        }

        return authorizations;
    }

}
