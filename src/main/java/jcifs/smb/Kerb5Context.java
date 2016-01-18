package jcifs.smb;


import java.security.Key;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;


/**
 * This class used to provide Kerberos feature when setup GSSContext.
 * 
 * @author Shun
 */
class Kerb5Context {

    private static final String OID = "1.2.840.113554.1.2.2";
    private GSSContext gssContext;


    Kerb5Context ( String host, String service, String name, int userLifetime, int contextLifetime, String realm ) throws GSSException {
        GSSManager manager = GSSManager.getInstance();
        Oid oid = null;
        GSSName serviceName = null;
        GSSName clientName = null;
        GSSCredential clientCreds = null;

        oid = new Oid(OID);

        if ( realm != null ) {
            serviceName = manager.createName(service + "/" + host + "@" + realm, new Oid("1.2.840.113554.1.2.2.1"), oid);
        }
        else {
            serviceName = manager.createName(service + "@" + host, GSSName.NT_HOSTBASED_SERVICE, oid);
        }
        if ( name != null ) {
            clientName = manager.createName(name, GSSName.NT_USER_NAME, oid);
            clientCreds = manager.createCredential(clientName, userLifetime, oid, GSSCredential.INITIATE_ONLY);
        }
        this.gssContext = manager.createContext(serviceName, oid, clientCreds, contextLifetime);
    }


    GSSContext getGSSContext () {
        return this.gssContext;
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


    public void dispose () throws GSSException {
        if ( this.gssContext != null ) {
            this.gssContext.dispose();
        }
    }
}
