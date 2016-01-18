package jcifs.util.transport;


import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;


public class TransportException extends IOException {

    /**
     * 
     */
    private static final long serialVersionUID = 3743631204022885618L;
    private Throwable rootCause;


    public TransportException () {}


    public TransportException ( String msg ) {
        super(msg);
    }


    public TransportException ( Throwable rootCause ) {
        this.rootCause = rootCause;
    }


    public TransportException ( String msg, Throwable rootCause ) {
        super(msg);
        this.rootCause = rootCause;
    }


    public Throwable getRootCause () {
        return this.rootCause;
    }


    @Override
    public String toString () {
        if ( this.rootCause != null ) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            this.rootCause.printStackTrace(pw);
            return super.toString() + "\n" + sw;
        }
        return super.toString();
    }
}
