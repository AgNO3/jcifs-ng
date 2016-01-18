/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs.context;


import jcifs.CIFSContext;
import jcifs.smb.NtlmAuthenticator;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbCredentials;


/**
 * @author mbechler
 *
 */
public class CIFSContextCredentialWrapper extends CIFSContextWrapper implements CIFSContext {

    private SmbCredentials creds;


    /**
     * @param delegate
     */
    public CIFSContextCredentialWrapper ( AbstractCIFSContext delegate, SmbCredentials creds ) {
        super(delegate);
        this.creds = creds;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContextWrapper#getCredentials()
     */
    @Override
    public SmbCredentials getCredentials () {
        return this.creds;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.CIFSContext#renewCredentials(java.lang.String, java.lang.Throwable)
     */
    @Override
    public boolean renewCredentials ( String locationHint, Throwable error ) {
        NtlmAuthenticator auth = NtlmAuthenticator.getDefault();
        if ( auth != null ) {
            NtlmPasswordAuthentication newAuth = NtlmAuthenticator
                    .requestNtlmPasswordAuthentication(auth, locationHint, ( error instanceof SmbAuthException ) ? (SmbAuthException) error : null);
            if ( newAuth != null ) {
                this.creds = newAuth;
                return true;
            }
        }
        return false;
    }
}
