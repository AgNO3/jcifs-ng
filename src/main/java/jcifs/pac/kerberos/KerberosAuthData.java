package jcifs.pac.kerberos;


import java.security.Key;
import java.util.ArrayList;
import java.util.List;

import jcifs.pac.PACDecodingException;


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
