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
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.MalformedURLException;

import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.SmbConstants;
import jcifs.util.transport.TransportException;


/**
 * This InputStream can read bytes from a file on an SMB file server. Offsets are 64 bits.
 */

public class SmbFileInputStream extends InputStream {

    private static final Logger log = Logger.getLogger(SmbFileInputStream.class);

    private long fp;
    private int readSize, readSizeFile, openFlags, access;
    private byte[] tmp = new byte[1];

    SmbFile file;


    /**
     * @param url
     * @param tc
     */
    public SmbFileInputStream ( String url, CIFSContext tc ) throws SmbException, MalformedURLException {
        this(new SmbFile(url, tc));
    }


    /**
     * Creates an {@link java.io.InputStream} for reading bytes from a file on
     * an SMB server represented by the {@link jcifs.smb.SmbFile} parameter. See
     * {@link jcifs.smb.SmbFile} for a detailed description and examples of
     * the smb URL syntax.
     *
     * @param file
     *            An <code>SmbFile</code> specifying the file to read from
     */

    public SmbFileInputStream ( SmbFile file ) throws SmbException {
        this(file, SmbFile.O_RDONLY);
    }


    SmbFileInputStream ( SmbFile file, int openFlags ) throws SmbException {
        this.file = file;
        this.openFlags = openFlags & 0xFFFF;
        this.access = ( openFlags >>> 16 ) & 0xFFFF;
        if ( file.type != SmbFile.TYPE_NAMED_PIPE ) {
            file.open(openFlags, this.access, SmbFile.ATTR_NORMAL, 0);
            this.openFlags &= ~ ( SmbFile.O_CREAT | SmbFile.O_TRUNC );
        }
        else {
            file.connect0();
        }
        this.readSize = Math.min(file.tree.session.getTransport().rcv_buf_size - 70, file.tree.session.getTransport().server.maxBufferSize - 70);

        boolean isSignatureActive = file.tree.session.getTransport().server.signaturesRequired
                || ( file.tree.session.getTransport().server.signaturesEnabled && file.getTransportContext().getConfig().isSigningPreferred() );
        if ( file.tree.session.getTransport().hasCapability(SmbConstants.CAP_LARGE_READX) && !isSignatureActive ) {
            this.readSizeFile = Math.min(file.getTransportContext().getConfig().getRecieveBufferSize() - 70, 0xFFFF - 70);
        }
        else {
            this.readSizeFile = this.readSize;
        }
    }


    protected IOException seToIoe ( SmbException se ) {
        IOException ioe = se;
        Throwable root = se.getRootCause();
        if ( root instanceof TransportException ) {
            ioe = (TransportException) root;
            root = ( (TransportException) ioe ).getRootCause();
        }
        if ( root instanceof InterruptedException ) {
            ioe = new InterruptedIOException(root.getMessage());
            ioe.initCause(root);
        }
        return ioe;
    }


    /**
     * Closes this input stream and releases any system resources associated with the stream.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public void close () throws IOException {
        try {
            this.file.close();
            this.tmp = null;
        }
        catch ( SmbException se ) {
            throw seToIoe(se);
        }
    }


    /**
     * Reads a byte of data from this input stream.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public int read () throws IOException {
        // need oplocks to cache otherwise use BufferedInputStream
        if ( read(this.tmp, 0, 1) == -1 ) {
            return -1;
        }
        return this.tmp[ 0 ] & 0xFF;
    }


    /**
     * Reads up to b.length bytes of data from this input stream into an array of bytes.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public int read ( byte[] b ) throws IOException {
        return read(b, 0, b.length);
    }


    /**
     * Reads up to len bytes of data from this input stream into an array of bytes.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public int read ( byte[] b, int off, int len ) throws IOException {
        return readDirect(b, off, len);
    }


    public int readDirect ( byte[] b, int off, int len ) throws IOException {
        if ( len <= 0 ) {
            return 0;
        }
        long start = this.fp;

        if ( this.tmp == null ) {
            throw new IOException("Bad file descriptor");
        }
        // ensure file is open
        this.file.open(this.openFlags, this.access, SmbFile.ATTR_NORMAL, 0);

        /*
         * Read AndX Request / Response
         */

        if ( log.isDebugEnabled() ) {
            log.debug("read: fid=" + this.file.fid + ",off=" + off + ",len=" + len);
        }

        SmbComReadAndXResponse response = new SmbComReadAndXResponse(getSession().getConfig(), b, off);

        if ( this.file.type == SmbFile.TYPE_NAMED_PIPE ) {
            response.responseTimeout = 0;
        }

        int r, n;
        do {
            int blockSize = ( this.file.getType() == SmbFile.TYPE_FILESYSTEM ) ? this.readSizeFile : this.readSize;
            r = len > blockSize ? blockSize : len;

            if ( log.isDebugEnabled() ) {
                log.debug("read: len=" + len + ",r=" + r + ",fp=" + this.fp);
            }

            try {
                SmbComReadAndX request = new SmbComReadAndX(getSession().getConfig(), this.file.fid, this.fp, r, null);
                if ( this.file.type == SmbFile.TYPE_NAMED_PIPE ) {
                    request.minCount = request.maxCount = request.remaining = 1024;
                }
                this.file.send(request, response);
            }
            catch ( SmbException se ) {
                if ( this.file.type == SmbFile.TYPE_NAMED_PIPE && se.getNtStatus() == NtStatus.NT_STATUS_PIPE_BROKEN ) {
                    return -1;
                }
                throw seToIoe(se);
            }
            if ( ( n = response.dataLength ) <= 0 ) {
                return (int) ( ( this.fp - start ) > 0L ? this.fp - start : -1 );
            }
            this.fp += n;
            len -= n;
            response.off += n;
        }
        while ( len > 0 && n == r );

        return (int) ( this.fp - start );
    }


    private SmbSession getSession () {
        return this.file.tree.session;
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
        SmbNamedPipe pipe;
        TransPeekNamedPipe req;
        TransPeekNamedPipeResponse resp;

        if ( this.file.type != SmbFile.TYPE_NAMED_PIPE ) {
            return 0;
        }

        try {
            pipe = (SmbNamedPipe) this.file;
            this.file.open(SmbFile.O_EXCL, pipe.pipeType & 0xFF0000, SmbFile.ATTR_NORMAL, 0);

            req = new TransPeekNamedPipe(getSession().getConfig(), this.file.unc, this.file.fid);
            resp = new TransPeekNamedPipeResponse(getSession().getConfig(), pipe);

            pipe.send(req, resp);
            if ( resp.status == TransPeekNamedPipeResponse.STATUS_DISCONNECTED
                    || resp.status == TransPeekNamedPipeResponse.STATUS_SERVER_END_CLOSED ) {
                this.file.opened = false;
                return 0;
            }
            return resp.available;
        }
        catch ( SmbException se ) {
            throw seToIoe(se);
        }
    }


    /**
     * Skip n bytes of data on this stream. This operation will not result
     * in any IO with the server. Unlink <tt>InputStream</tt> value less than
     * the one provided will not be returned if it exceeds the end of the file
     * (if this is a problem let us know).
     */
    @Override
    public long skip ( long n ) throws IOException {
        if ( n > 0 ) {
            this.fp += n;
            return n;
        }
        return 0;
    }

}
