/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: Mar 15, 2017 by mbechler
 */
package jcifs.smb;


import org.apache.log4j.Logger;

import jcifs.SmbConstants;


/**
 * @author mbechler
 *
 */
public class SmbPipeHandle implements AutoCloseable {

    private static final Logger log = Logger.getLogger(SmbPipeHandle.class);

    private final SmbNamedPipe pipe;
    private final boolean transact;
    private final boolean call;

    private final int openFlags;
    private final int access;
    private volatile boolean open = true;

    private SmbFileHandleImpl handle;
    private SmbPipeOutputStream output;
    private SmbPipeInputStream input;

    private final String uncPath;


    /**
     * @param pipe
     */
    public SmbPipeHandle ( SmbNamedPipe pipe ) {
        this.pipe = pipe;
        this.transact = ( pipe.getPipeType() & SmbNamedPipe.PIPE_TYPE_TRANSACT ) == SmbNamedPipe.PIPE_TYPE_TRANSACT;
        this.call = ( pipe.getPipeType() & SmbNamedPipe.PIPE_TYPE_CALL ) == SmbNamedPipe.PIPE_TYPE_CALL;
        this.openFlags = ( pipe.getPipeType() & 0xFFFF00FF ) | SmbFile.O_EXCL;
        this.access = ( pipe.getPipeType() >>> 16 ) & 0xFFFF;
        this.uncPath = this.pipe.getUncPath();
    }


    /**
     * @return the pipe
     */
    public SmbNamedPipe getPipe () {
        return this.pipe;
    }


    SmbTreeHandleImpl ensureTreeConnected () throws SmbException {
        return this.pipe.ensureTreeConnected();
    }


    /**
     * @return the uncPath
     */
    public String getUncPath () {
        return this.uncPath;
    }


    /**
     * @return whether the FD is open and valid
     */
    public boolean isOpen () {
        return this.open && this.handle != null && this.handle.isValid();
    }


    /**
     * @return whether the FD was previously open but became invalid
     */
    public boolean isStale () {
        return !this.open || ( this.handle != null && !this.handle.isValid() );
    }


    synchronized SmbFileHandleImpl ensureOpen () throws SmbException {
        if ( !this.open ) {
            throw new SmbException("Pipe handle already closed");
        }

        if ( !isOpen() ) {
            try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
                // TODO: wait for pipe, still not sure when this needs to be called exactly
                if ( this.uncPath.startsWith("\\pipe\\") ) {
                    th.send(new TransWaitNamedPipe(th.getConfig(), this.uncPath), new TransWaitNamedPipeResponse(th.getConfig()));
                }

                // one extra acquire to keep this open till the stream is released
                this.handle = this.pipe.openUnshared(this.openFlags, this.access | SmbConstants.FILE_WRITE_DATA, SmbFile.ATTR_NORMAL, 0).acquire();
                return this.handle;
            }

        }
        log.trace("Pipe already open");
        return this.handle.acquire();
    }


    /**
     * 
     * @return this pipe's input stream
     * @throws SmbException
     */
    public SmbPipeInputStream getInput () throws SmbException {

        if ( !this.open ) {
            throw new SmbException("Already closed");
        }

        if ( this.input != null ) {
            return this.input;
        }

        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            if ( this.transact ) {
                this.input = new TransactNamedPipeInputStream(this, th);
            }
            else if ( this.call ) {
                this.input = new TransactNamedPipeInputStream(this, th);
            }
            else {
                this.input = new SmbPipeInputStream(this, th);
            }
        }
        return this.input;
    }


    /**
     * 
     * @return this pipe's output stream
     * @throws SmbException
     */
    public SmbPipeOutputStream getOutput () throws SmbException {
        if ( !this.open ) {
            throw new SmbException("Already closed");
        }

        if ( this.output != null ) {
            return this.output;
        }

        try ( SmbTreeHandleImpl th = this.ensureTreeConnected() ) {
            if ( this.transact ) {
                this.output = new TransactNamedPipeOutputStream(this, th);
            }
            else if ( this.call ) {
                this.output = new TransactCallNamedPipeOutputStream(this, th);
            }
            else {
                this.output = new SmbPipeOutputStream(this, th);
            }
        }
        return this.output;
    }


    /**
     * @return the pipe type
     */
    public int getPipeType () {
        return this.pipe.getPipeType();
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    public synchronized void close () throws SmbException {
        boolean wasOpen = isOpen();
        this.open = false;
        if ( this.input != null ) {
            this.input.close();
            this.input = null;
        }

        if ( this.output != null ) {
            this.output.close();
            this.output = null;
        }
        if ( wasOpen ) {
            this.handle.close();
        }
        this.handle = null;
    }

}
