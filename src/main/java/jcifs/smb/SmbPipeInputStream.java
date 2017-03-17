/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: Mar 15, 2017 by mbechler
 */
package jcifs.smb;


import java.io.IOException;


/**
 * @author mbechler
 *
 */
public class SmbPipeInputStream extends SmbFileInputStream {

    private SmbPipeHandle handle;


    /**
     * @param handle
     * @param th
     * @throws SmbException
     */
    public SmbPipeInputStream ( SmbPipeHandle handle, SmbTreeHandleImpl th ) throws SmbException {
        super(handle.getPipe(), th);
        this.handle = handle;
    }


    protected synchronized SmbTreeHandleImpl ensureTreeConnected () throws SmbException {
        return this.handle.ensureTreeConnected();
    }


    @Override
    protected synchronized SmbFileHandleImpl ensureOpen () throws SmbException {
        return this.handle.ensureOpen();
    }


    /**
     * This stream class is unbuffered. Therefore this method will always
     * return 0 for streams connected to regular files. However, a
     * stream created from a Named Pipe this method will query the server using a
     * "peek named pipe" operation and return the number of available bytes
     * on the server.
     */
    @Override
    public int available () throws IOException {
        try ( SmbFileHandleImpl fd = this.handle.ensureOpen();
              SmbTreeHandleImpl th = fd.getTree() ) {
            TransPeekNamedPipe req = new TransPeekNamedPipe(th.getConfig(), this.handle.getUncPath(), fd.getFid());
            TransPeekNamedPipeResponse resp = new TransPeekNamedPipeResponse(th.getConfig());
            th.send(req, resp);
            if ( resp.status == TransPeekNamedPipeResponse.STATUS_DISCONNECTED
                    || resp.status == TransPeekNamedPipeResponse.STATUS_SERVER_END_CLOSED ) {
                fd.markClosed();
                return 0;
            }
            return resp.available;
        }
        catch ( SmbException se ) {
            throw seToIoe(se);
        }
    }


    @Override
    public void close () {
        // ignore, the shared file descriptor is closed by the pipe handle
    }
}
