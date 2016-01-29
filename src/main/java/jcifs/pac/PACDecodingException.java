package jcifs.pac;


import jcifs.CIFSException;


public class PACDecodingException extends CIFSException {

    private static final long serialVersionUID = 1L;


    public PACDecodingException () {
        this(null, null);
    }


    public PACDecodingException ( String message ) {
        this(message, null);
    }


    public PACDecodingException ( Throwable cause ) {
        this(null, cause);
    }


    public PACDecodingException ( String message, Throwable cause ) {
        super(message, cause);
    }

}
