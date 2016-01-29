package jcifs.pac;


import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;


public class PacSignature {

    private int type;
    private byte[] checksum;


    public PacSignature ( byte[] data ) throws PACDecodingException {
        try {
            PacDataInputStream bufferStream = new PacDataInputStream(new DataInputStream(new ByteArrayInputStream(data)));

            this.type = bufferStream.readInt();
            this.checksum = new byte[bufferStream.available()];
            bufferStream.readFully(this.checksum);
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed PAC signature", e);
        }
    }


    public int getType () {
        return this.type;
    }


    public byte[] getChecksum () {
        return this.checksum;
    }

}
