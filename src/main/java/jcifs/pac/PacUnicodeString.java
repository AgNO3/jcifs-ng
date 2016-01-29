package jcifs.pac;

public class PacUnicodeString {

    private short length;
    private short maxLength;
    private int pointer;


    public PacUnicodeString ( short length, short maxLength, int pointer ) {
        super();
        this.length = length;
        this.maxLength = maxLength;
        this.pointer = pointer;
    }


    public short getLength () {
        return this.length;
    }


    public short getMaxLength () {
        return this.maxLength;
    }


    public int getPointer () {
        return this.pointer;
    }


    public String check ( String string ) throws PACDecodingException {
        if ( this.pointer == 0 && string != null )
            throw new PACDecodingException("Non-empty string");

        int expected = this.length / 2;
        if ( string.length() != expected ) {
            throw new PACDecodingException("Invalid string length, expected " + expected + ", have " + string.length());
        }

        return string;
    }
}
