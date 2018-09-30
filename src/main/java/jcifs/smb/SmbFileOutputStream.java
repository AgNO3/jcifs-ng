/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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
import java.io.OutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.internal.fscc.FileEndOfFileInformation;
import jcifs.internal.smb1.com.SmbComWrite;
import jcifs.internal.smb1.com.SmbComWriteAndX;
import jcifs.internal.smb1.com.SmbComWriteAndXResponse;
import jcifs.internal.smb1.com.SmbComWriteResponse;
import jcifs.internal.smb2.info.Smb2SetInfoRequest;
import jcifs.internal.smb2.io.Smb2WriteRequest;
import jcifs.internal.smb2.io.Smb2WriteResponse;


/**
 * This <code>OutputStream</code> can write bytes to a file on an SMB file server.
 */

public class SmbFileOutputStream extends OutputStream {

    private static final Logger log = LoggerFactory.getLogger(SmbFileOutputStream.class);

    private SmbFile file;
    private boolean append, useNTSmbs;
    private int openFlags, access, writeSize, writeSizeFile;
    private long fp;
    private byte[] tmp = new byte[1];
    private SmbComWriteAndX reqx;
    private SmbComWriteAndXResponse rspx;
    private SmbComWrite req;
    private SmbComWriteResponse rsp;

    private SmbFileHandleImpl handle;

    private int sharing;

    private final boolean smb2;


    /**
     * Creates an {@link java.io.OutputStream} for writing bytes to a file on
     * an SMB server represented by the {@link jcifs.smb.SmbFile} parameter. See
     * {@link jcifs.smb.SmbFile} for a detailed description and examples of
     * the smb URL syntax.
     *
     * @param file
     *            An <code>SmbFile</code> specifying the file to write to
     * @throws SmbException
     */
    public SmbFileOutputStream ( SmbFile file ) throws SmbException {
        this(file, false);
    }


    /**
     * Creates an {@link java.io.OutputStream} for writing bytes to a file
     * on an SMB server addressed by the <code>SmbFile</code> parameter. See
     * {@link jcifs.smb.SmbFile} for a detailed description and examples of
     * the smb URL syntax. If the second argument is <code>true</code>, then
     * bytes will be written to the end of the file rather than the beginning.
     * 
     * @param file
     *            An <code>SmbFile</code> representing the file to write to
     * @param append
     *            Append to the end of file
     * @throws SmbException
     */

    public SmbFileOutputStream ( SmbFile file, boolean append ) throws SmbException {
        this(
            file,
            append,
            append ? SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_APPEND
                    : SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            0,
            SmbConstants.DEFAULT_SHARING);
    }


    SmbFileOutputStream ( SmbFile file, boolean append, int openFlags, int access, int sharing ) throws SmbException {
        this.file = file;
        this.append = append;
        this.openFlags = openFlags;
        this.sharing = sharing;
        this.access = access | SmbConstants.FILE_WRITE_DATA;

        try ( SmbTreeHandleImpl th = file.ensureTreeConnected() ) {
            this.smb2 = th.isSMB2();
            try ( SmbFileHandleImpl fh = ensureOpen() ) {
                if ( append ) {
                    this.fp = fh.getInitialSize();
                }
                init(th);
                if ( !append && this.smb2 ) {
                    // no open option for truncating, need to truncate the file
                    Smb2SetInfoRequest treq = new Smb2SetInfoRequest(th.getConfig(), fh.getFileId());
                    treq.setFileInformation(new FileEndOfFileInformation(0));
                    th.send(treq, RequestParam.NO_RETRY);
                }
            }
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    SmbFileOutputStream ( SmbFile file, SmbTreeHandleImpl th, SmbFileHandleImpl handle, int openFlags, int access, int sharing )
            throws CIFSException {
        this.file = file;
        this.handle = handle;
        this.openFlags = openFlags;
        this.access = access;
        this.sharing = sharing;
        this.append = false;
        this.smb2 = th.isSMB2();
        init(th);
    }


    /**
     * @param th
     * @throws SmbException
     */
    protected final void init ( SmbTreeHandleImpl th ) throws CIFSException {
        int sendBufferSize = th.getSendBufferSize();
        if ( this.smb2 ) {
            this.writeSize = sendBufferSize;
            this.writeSizeFile = sendBufferSize;
            return;
        }

        this.openFlags &= ~ ( SmbConstants.O_CREAT | SmbConstants.O_TRUNC ); /* in case we close and reopen */
        this.writeSize = sendBufferSize - 70;

        this.useNTSmbs = th.hasCapability(SmbConstants.CAP_NT_SMBS);
        if ( !this.useNTSmbs ) {
            log.debug("No support for NT SMBs");
        }

        // there seems to be a bug with some servers that causes corruption if using signatures +
        // CAP_LARGE_WRITE
        if ( th.hasCapability(SmbConstants.CAP_LARGE_WRITEX) && !th.areSignaturesActive() ) {
            this.writeSizeFile = Math.min(th.getConfig().getSendBufferSize() - 70, 0xFFFF - 70);
        }
        else {
            log.debug("No support or SMB signing is enabled, not enabling large writes");
            this.writeSizeFile = this.writeSize;
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Negotiated file write size is " + this.writeSizeFile);
        }

        if ( this.useNTSmbs ) {
            this.reqx = new SmbComWriteAndX(th.getConfig());
            this.rspx = new SmbComWriteAndXResponse(th.getConfig());
        }
        else {
            this.req = new SmbComWrite(th.getConfig());
            this.rsp = new SmbComWriteResponse(th.getConfig());
        }
    }


    /**
     * Closes this output stream and releases any system resources associated
     * with it.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public void close () throws IOException {
        try {
            if ( this.handle.isValid() ) {
                this.handle.close();
            }
        }
        finally {
            this.file.clearAttributeCache();
            this.tmp = null;
        }
    }


    /**
     * Writes the specified byte to this file output stream.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public void write ( int b ) throws IOException {
        this.tmp[ 0 ] = (byte) b;
        write(this.tmp, 0, 1);
    }


    /**
     * Writes b.length bytes from the specified byte array to this
     * file output stream.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public void write ( byte[] b ) throws IOException {
        write(b, 0, b.length);
    }


    /**
     * @return whether the stream is open
     */
    public boolean isOpen () {
        return this.handle != null && this.handle.isValid();
    }


    protected synchronized SmbFileHandleImpl ensureOpen () throws CIFSException {
        if ( !isOpen() ) {
            // one extra acquire to keep this open till the stream is released
            this.handle = this.file.openUnshared(this.openFlags, this.access, this.sharing, SmbConstants.ATTR_NORMAL, 0).acquire();
            if ( this.append ) {
                this.fp = this.handle.getInitialSize();
                if ( log.isDebugEnabled() ) {
                    log.debug("File pointer is at " + this.fp);
                }
            }
            return this.handle;
        }

        log.trace("File already open");
        return this.handle.acquire();
    }


    protected SmbTreeHandleImpl ensureTreeConnected () throws CIFSException {
        return this.file.ensureTreeConnected();
    }


    /**
     * Writes len bytes from the specified byte array starting at
     * offset off to this file output stream.
     *
     * @param b
     *            The array
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public void write ( byte[] b, int off, int len ) throws IOException {
        writeDirect(b, off, len, 0);
    }


    /**
     * Just bypasses TransWaitNamedPipe - used by DCERPC bind.
     * 
     * @param b
     * @param off
     * @param len
     * @param flags
     * @throws IOException
     */
    public void writeDirect ( byte[] b, int off, int len, int flags ) throws IOException {
        if ( len <= 0 ) {
            return;
        }

        if ( this.tmp == null ) {
            throw new IOException("Bad file descriptor");
        }

        try ( SmbFileHandleImpl fh = ensureOpen();
              SmbTreeHandleImpl th = fh.getTree() ) {
            if ( log.isDebugEnabled() ) {
                log.debug("write: fid=" + fh + ",off=" + off + ",len=" + len);
            }

            int w;
            do {
                int blockSize = ( this.file.getType() == SmbConstants.TYPE_FILESYSTEM ) ? this.writeSizeFile : this.writeSize;
                w = len > blockSize ? blockSize : len;

                if ( this.smb2 ) {
                    Smb2WriteRequest wr = new Smb2WriteRequest(th.getConfig(), fh.getFileId());
                    wr.setOffset(this.fp);
                    wr.setData(b, off, w);

                    Smb2WriteResponse resp = th.send(wr, RequestParam.NO_RETRY);
                    long cnt = resp.getCount();
                    this.fp += cnt;
                    len -= cnt;
                    off += cnt;
                }
                else if ( this.useNTSmbs ) {
                    this.reqx.setParam(fh.getFid(), this.fp, len - w, b, off, w);
                    if ( ( flags & 1 ) != 0 ) {
                        this.reqx.setParam(fh.getFid(), this.fp, len, b, off, w);
                        this.reqx.setWriteMode(0x8);
                    }
                    else {
                        this.reqx.setWriteMode(0);
                    }

                    th.send(this.reqx, this.rspx, RequestParam.NO_RETRY);
                    long cnt = this.rspx.getCount();
                    this.fp += cnt;
                    len -= cnt;
                    off += cnt;
                }
                else {
                    if ( log.isTraceEnabled() ) {
                        log.trace(String.format("Wrote at %d remain %d off %d len %d", this.fp, len - w, off, w));
                    }
                    this.req.setParam(fh.getFid(), this.fp, len - w, b, off, w);
                    th.send(this.req, this.rsp);
                    long cnt = this.rsp.getCount();
                    this.fp += cnt;
                    len -= cnt;
                    off += cnt;
                    if ( log.isTraceEnabled() ) {
                        log.trace(String.format("Wrote at %d remain %d off %d len %d", this.fp, len - w, off, w));
                    }
                }

            }
            while ( len > 0 );
        }
    }

}
