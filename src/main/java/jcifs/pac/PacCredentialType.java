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
package jcifs.pac;


/**
 * Structure representing the PAC_CREDENTIAL_TYPE record
 * 
 * @author jbbugeau
 */
@SuppressWarnings ( "javadoc" )
public class PacCredentialType {

    private static final int MINIMAL_BUFFER_SIZE = 32;

    private byte[] credentialType;


    public PacCredentialType ( byte[] data ) throws PACDecodingException {
        this.credentialType = data;
        if ( !isCredentialTypeCorrect() ) {
            throw new PACDecodingException("Invalid PAC credential type");
        }
    }


    public boolean isCredentialTypeCorrect () {
        return this.credentialType != null && this.credentialType.length < MINIMAL_BUFFER_SIZE;
    }

}
