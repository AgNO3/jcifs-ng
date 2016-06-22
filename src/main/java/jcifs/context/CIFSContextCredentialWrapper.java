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
