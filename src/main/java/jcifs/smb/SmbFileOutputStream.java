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

import org.apache.log4j.Logger;

import jcifs.SmbConstants;


/**
 * This <code>OutputStream</code> can write bytes to a file on an SMB file server.
 */

public class SmbFileOutputStream extends OutputStream {

    private static final Logger log = Logger.getLogger(SmbFileOutputStream.class);

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
        this(file, append, append ? SmbFile.O_CREAT | SmbFile.O_WRONLY | SmbFile.O_APPEND : SmbFile.O_CREAT | SmbFile.O_WRONLY | SmbFile.O_TRUNC);
    }


    SmbFileOutputStream ( SmbFile file, boolean append, int openFlags ) throws SmbException {
        this.file = file;
        this.append = append;
        this.openFlags = openFlags;
        this.access = ( openFlags >>> 16 ) & 0xFFFF;

        try ( SmbTreeHandleImpl th = file.ensureTreeConnected() ) {
            try ( SmbFileHandle h = ensureOpen() ) {
                if ( append ) {
                    // do this after file.open so we get the actual position (and also don't waste another call)
                    try {
                        this.fp = file.length();
                    }
                    catch ( SmbAuthException sae ) {
                        throw sae;
                    }
                    catch ( SmbException se ) {
                        log.warn("Error determining length in append mode", se);
                        this.fp = 0L;
                    }
                }
                init(th);
            }
        }
    }


    SmbFileOutputStream ( SmbFile file, SmbTreeHandleImpl th ) throws SmbException {
        this.file = file;
        this.append = false;
        init(th);
    }


    /**
     * @param th
     * @throws SmbException
     */
    protected final void init ( SmbTreeHandleImpl th ) throws SmbException {
        this.openFlags &= ~ ( SmbFile.O_CREAT | SmbFile.O_TRUNC ); /* in case close and reopen */
        this.writeSize = th.getSendBufferSize() - 70;

        this.useNTSmbs = th.hasCapability(SmbConstants.CAP_NT_SMBS);
        if ( !this.useNTSmbs ) {
            log.debug("No support for NT SMBs");
        }

        // there seems to be a bug with some servers that causes corruption if using signatures +
        // CAP_LARGE_WRITE
        if ( th.hasCapability(SmbConstants.CAP_LARGE_WRITEX) && !th.areSignaturesActive() ) {
            this.writeSizeFile = Math.min(th.getSendBufferSize() - 70, 0xFFFF - 70);
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


    protected synchronized SmbFileHandleImpl ensureOpen () throws SmbException {
        if ( !isOpen() ) {
            // one extra acquire to keep this open till the stream is released
            this.handle = this.file.openUnshared(this.openFlags, this.access | SmbConstants.FILE_WRITE_DATA, SmbFile.ATTR_NORMAL, 0).acquire();
            if ( this.append ) {
                this.fp = this.file.length();
            }
            return this.handle;
        }

        log.trace("File already open");
        return this.handle.acquire();
    }


    protected SmbTreeHandleImpl ensureTreeConnected () throws SmbException {
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
                int blockSize = ( this.file.getType() == SmbFile.TYPE_FILESYSTEM ) ? this.writeSizeFile : this.writeSize;
                w = len > blockSize ? blockSize : len;

                if ( this.useNTSmbs ) {
                    this.reqx.setParam(fh.getFid(), this.fp, len - w, b, off, w);
                    if ( ( flags & 1 ) != 0 ) {
                        this.reqx.setParam(fh.getFid(), this.fp, len, b, off, w);
                        this.reqx.writeMode = 0x8;
                    }
                    else {
                        this.reqx.writeMode = 0;
                    }

                    th.send(this.reqx, this.rspx);
                    this.fp += this.rspx.count;
                    len -= this.rspx.count;
                    off += this.rspx.count;
                }
                else {
                    if ( log.isTraceEnabled() ) {
                        log.trace(String.format("Wrote at %d remain %d off %d len %d", this.fp, len - w, off, w));
                    }
                    this.req.setParam(fh.getFid(), this.fp, len - w, b, off, w);
                    th.send(this.req, this.rsp);
                    this.fp += this.rsp.count;
                    len -= this.rsp.count;
                    off += this.rsp.count;
                    if ( log.isTraceEnabled() ) {
                        log.trace(String.format("Wrote at %d remain %d off %d len %d", this.fp, len - w, off, w));
                    }
                }

            }
            while ( len > 0 );
        }
    }

}
