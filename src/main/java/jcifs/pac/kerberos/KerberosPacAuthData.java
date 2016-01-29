package jcifs.pac.kerberos;


import java.security.Key;

import jcifs.pac.PACDecodingException;
import jcifs.pac.Pac;


public class KerberosPacAuthData extends KerberosAuthData {

    private Pac pac;


    public KerberosPacAuthData ( byte[] token, Key key ) throws PACDecodingException {
        this.pac = new Pac(token, key);
    }


    public Pac getPac () {
        return this.pac;
    }

}
