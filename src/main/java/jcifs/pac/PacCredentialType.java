package jcifs.pac;

/**
 * Structure representing the PAC_CREDENTIAL_TYPE record
 * 
 * @author jbbugeau
 */
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
