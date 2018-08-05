/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package jcifs.smb;


import java.io.IOException;

import jcifs.CIFSException;
import jcifs.internal.smb1.trans.TransPeekNamedPipe;
import jcifs.internal.smb1.trans.TransPeekNamedPipeResponse;
import jcifs.internal.smb2.ioctl.Smb2IoctlRequest;
import jcifs.internal.smb2.ioctl.Smb2IoctlResponse;
import jcifs.internal.smb2.ioctl.SrvPipePeekResponse;


/**
 * @author mbechler
 *
 */
public class SmbPipeInputStream extends SmbFileInputStream {

    private SmbPipeHandleImpl handle;


    /**
     * @param handle
     * @param th
     * @throws SmbException
     */
    SmbPipeInputStream ( SmbPipeHandleImpl handle, SmbTreeHandleImpl th ) throws CIFSException {
        super(handle.getPipe(), th, null);
        this.handle = handle;
    }


    protected synchronized SmbTreeHandleImpl ensureTreeConnected () throws CIFSException {
        return this.handle.ensureTreeConnected();
    }


    @Override
    protected synchronized SmbFileHandleImpl ensureOpen () throws CIFSException {
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
            if ( th.isSMB2() ) {
                Smb2IoctlRequest req = new Smb2IoctlRequest(th.getConfig(), Smb2IoctlRequest.FSCTL_PIPE_PEEK, fd.getFileId());
                req.setMaxOutputResponse(16);
                req.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
                Smb2IoctlResponse resp = th.send(req, RequestParam.NO_RETRY);
                return ((SrvPipePeekResponse)resp.getOutputData()).getReadDataAvailable();
            }
            TransPeekNamedPipe req = new TransPeekNamedPipe(th.getConfig(), this.handle.getUncPath(), fd.getFid());
            TransPeekNamedPipeResponse resp = new TransPeekNamedPipeResponse(th.getConfig());
            th.send(req, resp, RequestParam.NO_RETRY);
            if ( resp.getStatus() == TransPeekNamedPipeResponse.STATUS_DISCONNECTED
                    || resp.getStatus() == TransPeekNamedPipeResponse.STATUS_SERVER_END_CLOSED ) {
                fd.markClosed();
                return 0;
            }
            return resp.getAvailable();
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
