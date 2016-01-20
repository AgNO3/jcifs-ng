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


    /**
     * Creates an {@link java.io.OutputStream} for writing bytes to a file on
     * an SMB server represented by the {@link jcifs.smb.SmbFile} parameter. See
     * {@link jcifs.smb.SmbFile} for a detailed description and examples of
     * the smb URL syntax.
     *
     * @param file
     *            An <code>SmbFile</code> specifying the file to write to
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
     */

    public SmbFileOutputStream ( SmbFile file, boolean append ) throws SmbException {
        this(file, append, append ? SmbFile.O_CREAT | SmbFile.O_WRONLY | SmbFile.O_APPEND : SmbFile.O_CREAT | SmbFile.O_WRONLY | SmbFile.O_TRUNC);
    }


    SmbFileOutputStream ( SmbFile file, boolean append, int openFlags ) throws SmbException {
        this.file = file;
        this.append = append;
        this.openFlags = openFlags;
        this.access = ( openFlags >>> 16 ) & 0xFFFF;
        if ( append ) {
            try {
                this.fp = file.length();
            }
            catch ( SmbAuthException sae ) {
                throw sae;
            }
            catch ( SmbException se ) {
                this.fp = 0L;
            }
        }
        if ( file instanceof SmbNamedPipe && file.unc.startsWith("\\pipe\\") ) {
            file.unc = file.unc.substring(5);
            file.send(
                new TransWaitNamedPipe(getSession().getConfig(), "\\pipe" + file.unc),
                new TransWaitNamedPipeResponse(getSession().getConfig()));
        }
        file.open(openFlags, this.access | SmbConstants.FILE_WRITE_DATA, SmbFile.ATTR_NORMAL, 0);
        this.openFlags &= ~ ( SmbFile.O_CREAT | SmbFile.O_TRUNC ); /* in case close and reopen */
        this.writeSize = file.tree.session.getTransport().snd_buf_size - 70;

        // there seems to be a bug with some servers that causes corruption if using signatures + CAP_LARGE_WRITE
        boolean isSignatureActive = file.tree.session.getTransport().server.signaturesRequired
                || ( file.tree.session.getTransport().server.signaturesEnabled && file.getTransportContext().getConfig().isSigningPreferred() );
        if ( file.tree.session.getTransport().hasCapability(SmbConstants.CAP_LARGE_WRITEX) && !isSignatureActive ) {
            this.writeSizeFile = Math.min(file.getTransportContext().getConfig().getSendBufferSize() - 70, 0xFFFF - 70);
        }
        else {
            this.writeSizeFile = this.writeSize;
        }

        this.useNTSmbs = file.tree.session.getTransport().hasCapability(SmbConstants.CAP_NT_SMBS);
        if ( this.useNTSmbs ) {
            this.reqx = new SmbComWriteAndX(getSession().getConfig());
            this.rspx = new SmbComWriteAndXResponse(getSession().getConfig());
        }
        else {
            this.req = new SmbComWrite(getSession().getConfig());
            this.rsp = new SmbComWriteResponse(getSession().getConfig());
        }
    }


    private SmbSession getSession () {
        return this.file.tree.session;
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
        this.file.close();
        this.tmp = null;
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


    public boolean isOpen () {
        return this.file.isOpen();
    }


    void ensureOpen () throws IOException {
        // ensure file is open
        if ( this.file.isOpen() == false ) {
            this.file.open(this.openFlags, this.access | SmbConstants.FILE_WRITE_DATA, SmbFile.ATTR_NORMAL, 0);
            if ( this.append ) {
                this.fp = this.file.length();
            }
        }
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
        if ( this.file.isOpen() == false && this.file instanceof SmbNamedPipe ) {
            this.file.send(
                new TransWaitNamedPipe(getSession().getConfig(), "\\pipe" + this.file.unc),
                new TransWaitNamedPipeResponse(getSession().getConfig()));
        }
        writeDirect(b, off, len, 0);
    }


    /**
     * Just bypasses TransWaitNamedPipe - used by DCERPC bind.
     */
    public void writeDirect ( byte[] b, int off, int len, int flags ) throws IOException {
        if ( len <= 0 ) {
            return;
        }

        if ( this.tmp == null ) {
            throw new IOException("Bad file descriptor");
        }
        ensureOpen();

        if ( log.isDebugEnabled() ) {
            log.debug("write: fid=" + this.file.fid + ",off=" + off + ",len=" + len);
        }

        int w;
        do {
            int blockSize = ( this.file.getType() == SmbFile.TYPE_FILESYSTEM ) ? this.writeSizeFile : this.writeSize;
            w = len > blockSize ? blockSize : len;

            w = len > this.writeSize ? this.writeSize : len;
            if ( this.useNTSmbs ) {
                this.reqx.setParam(this.file.fid, this.fp, len - w, b, off, w);
                if ( ( flags & 1 ) != 0 ) {
                    this.reqx.setParam(this.file.fid, this.fp, len, b, off, w);
                    this.reqx.writeMode = 0x8;
                }
                else {
                    this.reqx.writeMode = 0;
                }

                this.file.send(this.reqx, this.rspx);
                this.fp += this.rspx.count;
                len -= this.rspx.count;
                off += this.rspx.count;
            }
            else {
                this.req.setParam(this.file.fid, this.fp, len - w, b, off, w);
                this.fp += this.rsp.count;
                len -= this.rsp.count;
                off += this.rsp.count;
                this.file.send(this.req, this.rsp);
            }
        }
        while ( len > 0 );
    }

}
