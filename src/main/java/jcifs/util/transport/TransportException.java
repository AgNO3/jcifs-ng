package jcifs.util.transport;


import java.io.IOException;


public class TransportException extends IOException {

    /**
     * 
     */
    private static final long serialVersionUID = 3743631204022885618L;


    public TransportException () {}


    public TransportException ( String msg ) {
        super(msg);
    }


    public TransportException ( Throwable rootCause ) {
        super(rootCause);
    }


    public TransportException ( String msg, Throwable rootCause ) {
        super(msg, rootCause);
    }


    public Throwable getRootCause () {
        return getCause();
    }
}
