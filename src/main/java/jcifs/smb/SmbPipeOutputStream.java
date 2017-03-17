/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: Mar 15, 2017 by mbechler
 */
package jcifs.smb;


/**
 * @author mbechler
 *
 */
public class SmbPipeOutputStream extends SmbFileOutputStream {

    private SmbPipeHandle handle;


    /**
     * @param handle
     * @throws SmbException
     */
    SmbPipeOutputStream ( SmbPipeHandle handle, SmbTreeHandleImpl th ) throws SmbException {
        super(handle.getPipe(), th);
        this.handle = handle;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileOutputStream#isOpen()
     */
    @Override
    public boolean isOpen () {
        return this.handle.isOpen();
    }


    @Override
    protected synchronized SmbTreeHandleImpl ensureTreeConnected () throws SmbException {
        return this.handle.ensureTreeConnected();
    }


    @Override
    protected synchronized SmbFileHandleImpl ensureOpen () throws SmbException {
        return this.handle.ensureOpen();
    }


    @Override
    public void close () {
        // ignore, the shared file descriptor is closed by the pipe handle
    }
}
