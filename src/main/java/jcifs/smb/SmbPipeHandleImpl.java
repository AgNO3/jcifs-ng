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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.SmbPipeHandle;
import jcifs.SmbPipeResource;
import jcifs.internal.smb1.trans.TransCallNamedPipe;
import jcifs.internal.smb1.trans.TransCallNamedPipeResponse;
import jcifs.internal.smb1.trans.TransTransactNamedPipe;
import jcifs.internal.smb1.trans.TransTransactNamedPipeResponse;
import jcifs.internal.smb1.trans.TransWaitNamedPipe;
import jcifs.internal.smb1.trans.TransWaitNamedPipeResponse;
import jcifs.internal.smb2.ioctl.Smb2IoctlRequest;
import jcifs.internal.smb2.ioctl.Smb2IoctlResponse;
import jcifs.util.ByteEncodable;


/**
 * @author mbechler
 *
 */
class SmbPipeHandleImpl implements SmbPipeHandleInternal {

    private static final Logger log = LoggerFactory.getLogger(SmbPipeHandleImpl.class);

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

    private SmbTreeHandleImpl treeHandle;

    private int sharing = SmbConstants.DEFAULT_SHARING;


    /**
     * @param pipe
     */
    public SmbPipeHandleImpl ( SmbNamedPipe pipe ) {
        this.pipe = pipe;
        this.transact = ( pipe.getPipeType() & SmbPipeResource.PIPE_TYPE_TRANSACT ) == SmbPipeResource.PIPE_TYPE_TRANSACT;
        this.call = ( pipe.getPipeType() & SmbPipeResource.PIPE_TYPE_CALL ) == SmbPipeResource.PIPE_TYPE_CALL;
        this.openFlags = ( pipe.getPipeType() & 0xFFFF00FF ) | SmbConstants.O_EXCL;
        this.access = (pipe.getPipeType() & 7) | 0x20000;
        this.uncPath = this.pipe.getUncPath();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbPipeHandle#unwrap(java.lang.Class)
     */
    @SuppressWarnings ( "unchecked" )
    @Override
    public <T extends SmbPipeHandle> T unwrap ( Class<T> type ) {
        if ( type.isAssignableFrom(this.getClass()) ) {
            return (T) this;
        }
        throw new ClassCastException();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbPipeHandle#getPipe()
     */
    @Override
    public SmbNamedPipe getPipe () {
        return this.pipe;
    }


    @Override
    public SmbTreeHandleImpl ensureTreeConnected () throws CIFSException {
        if ( this.treeHandle == null ) {
            // extra acquire to keep the tree alive
            this.treeHandle = this.pipe.ensureTreeConnected();
        }
        return this.treeHandle.acquire();
    }


    public String getUncPath () {
        return this.uncPath;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbPipeHandle#isOpen()
     */
    @Override
    public boolean isOpen () {
        return this.open && this.handle != null && this.handle.isValid();
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbPipeHandleInternal#getSessionKey()
     */
    @Override
    public byte[] getSessionKey () throws CIFSException {
        try ( SmbTreeHandleImpl th = ensureTreeConnected();
              SmbSessionImpl sess = th.getSession() ) {
            return sess.getSessionKey();
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbPipeHandle#isStale()
     */
    @Override
    public boolean isStale () {
        return !this.open || ( this.handle != null && !this.handle.isValid() );
    }


    @Override
    public synchronized SmbFileHandleImpl ensureOpen () throws CIFSException {
        if ( !this.open ) {
            throw new SmbException("Pipe handle already closed");
        }

        if ( !isOpen() ) {
            try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {

                if ( th.isSMB2() ) {
                    this.handle = this.pipe.openUnshared(this.uncPath, this.openFlags, this.access, this.sharing, SmbConstants.ATTR_NORMAL, 0);
                    return this.handle.acquire();
                }

                // TODO: wait for pipe, still not sure when this needs to be called exactly
                if ( this.uncPath.startsWith("\\pipe\\") ) {
                    th.send(new TransWaitNamedPipe(th.getConfig(), this.uncPath), new TransWaitNamedPipeResponse(th.getConfig()));
                }

                if ( th.hasCapability(SmbConstants.CAP_NT_SMBS) || this.uncPath.startsWith("\\pipe\\") ) {
                    this.handle = this.pipe.openUnshared(this.openFlags, this.access, this.sharing, SmbConstants.ATTR_NORMAL, 0);
                }
                else {
                    // at least on samba, SmbComOpenAndX fails without the pipe prefix
                    this.handle = this.pipe
                            .openUnshared("\\pipe" + getUncPath(), this.openFlags, this.access, this.sharing, SmbConstants.ATTR_NORMAL, 0);
                }
                // one extra acquire to keep this open till the stream is released
                return this.handle.acquire();
            }

        }
        log.trace("Pipe already open");
        return this.handle.acquire();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbPipeHandle#getInput()
     */
    @Override
    public SmbPipeInputStream getInput () throws CIFSException {

        if ( !this.open ) {
            throw new SmbException("Already closed");
        }

        if ( this.input != null ) {
            return this.input;
        }

        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            this.input = new SmbPipeInputStream(this, th);
        }
        return this.input;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbPipeHandle#getOutput()
     */
    @Override
    public SmbPipeOutputStream getOutput () throws CIFSException {
        if ( !this.open ) {
            throw new SmbException("Already closed");
        }

        if ( this.output != null ) {
            return this.output;
        }

        try ( SmbTreeHandleImpl th = ensureTreeConnected() ) {
            this.output = new SmbPipeOutputStream(this, th);
        }
        return this.output;
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbPipeHandleInternal#sendrecv(byte[], int, int, byte[], int)
     */
    @SuppressWarnings ( "resource" )
    @Override
    public int sendrecv ( byte[] buf, int off, int length, byte[] inB, int maxRecvSize ) throws IOException {
        try ( SmbFileHandleImpl fh = ensureOpen();
              SmbTreeHandleImpl th = fh.getTree() ) {

            if ( th.isSMB2() ) {
                Smb2IoctlRequest req = new Smb2IoctlRequest(th.getConfig(), Smb2IoctlRequest.FSCTL_PIPE_TRANSCEIVE, fh.getFileId(), inB);
                req.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
                req.setInputData(new ByteEncodable(buf, off, length));
                req.setMaxOutputResponse(maxRecvSize);
                Smb2IoctlResponse resp = th.send(req, RequestParam.NO_RETRY);
                return resp.getOutputLength();
            }
            else if ( this.transact ) {
                TransTransactNamedPipe req = new TransTransactNamedPipe(th.getConfig(), fh.getFid(), buf, off, length);
                TransTransactNamedPipeResponse resp = new TransTransactNamedPipeResponse(th.getConfig(), inB);
                if ( ( getPipeType() & SmbPipeResource.PIPE_TYPE_DCE_TRANSACT ) == SmbPipeResource.PIPE_TYPE_DCE_TRANSACT ) {
                    req.setMaxDataCount(1024);
                }
                th.send(req, resp, RequestParam.NO_RETRY);
                return resp.getByteCount();
            }
            else if ( this.call ) {
                th.send(new TransWaitNamedPipe(th.getConfig(), this.uncPath), new TransWaitNamedPipeResponse(th.getConfig()));
                TransCallNamedPipeResponse resp = new TransCallNamedPipeResponse(th.getConfig(), inB);
                th.send(new TransCallNamedPipe(th.getConfig(), this.uncPath, buf, off, length), resp);
                return resp.getByteCount();
            }
            else {
                SmbPipeOutputStream out = getOutput();
                SmbPipeInputStream in = getInput();
                out.write(buf, off, length);
                return in.read(inB);
            }
        }
    }


    @Override
    public int recv ( byte[] buf, int off, int len ) throws IOException {
        return getInput().readDirect(buf, off, len);

    }


    @Override
    public void send ( byte[] buf, int off, int length ) throws IOException {
        getOutput().writeDirect(buf, off, length, 1);
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbPipeHandleInternal#getPipeType()
     */
    @Override
    public int getPipeType () {
        return this.pipe.getPipeType();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbPipeHandle#close()
     */
    @Override
    public synchronized void close () throws CIFSException {
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

        try {
            if ( wasOpen ) {
                this.handle.close();
            }
            else if ( this.handle != null ) {
                this.handle.release();
            }
            this.handle = null;
        }
        finally {
            if ( this.treeHandle != null ) {
                this.treeHandle.release();
            }
        }
    }

}
