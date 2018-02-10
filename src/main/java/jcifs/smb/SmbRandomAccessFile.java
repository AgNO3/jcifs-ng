/* jcifs smb client library in Java
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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
import java.net.MalformedURLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.SmbFileHandle;
import jcifs.SmbRandomAccess;
import jcifs.internal.fscc.FileEndOfFileInformation;
import jcifs.internal.smb1.com.SmbComReadAndX;
import jcifs.internal.smb1.com.SmbComReadAndXResponse;
import jcifs.internal.smb1.com.SmbComWrite;
import jcifs.internal.smb1.com.SmbComWriteAndX;
import jcifs.internal.smb1.com.SmbComWriteAndXResponse;
import jcifs.internal.smb1.com.SmbComWriteResponse;
import jcifs.internal.smb1.trans2.Trans2SetFileInformation;
import jcifs.internal.smb1.trans2.Trans2SetFileInformationResponse;
import jcifs.internal.smb2.info.Smb2SetInfoRequest;
import jcifs.internal.smb2.io.Smb2ReadRequest;
import jcifs.internal.smb2.io.Smb2ReadResponse;
import jcifs.internal.smb2.io.Smb2WriteRequest;
import jcifs.internal.smb2.io.Smb2WriteResponse;
import jcifs.util.Encdec;


/**
 * 
 * 
 *
 */
public class SmbRandomAccessFile implements SmbRandomAccess {

    private static final Logger log = LoggerFactory.getLogger(SmbRandomAccessFile.class);
    private static final int WRITE_OPTIONS = 0x0842;

    private SmbFile file;
    private long fp;
    private int openFlags, access = 0, readSize, writeSize, options = 0;
    private byte[] tmp = new byte[8];
    private SmbComWriteAndXResponse write_andx_resp = null;

    private boolean largeReadX;
    private final boolean unsharedFile;

    private SmbFileHandleImpl handle;

    private int sharing;


    /**
     * Instantiate a random access file from URL
     * 
     * @param url
     * @param mode
     * @param sharing
     * @param tc
     * @throws SmbException
     * @throws MalformedURLException
     */
    @SuppressWarnings ( "resource" )
    public SmbRandomAccessFile ( String url, String mode, int sharing, CIFSContext tc ) throws SmbException, MalformedURLException {
        this(new SmbFile(url, tc), mode, sharing, true);
    }


    /**
     * Instantiate a random access file from a {@link SmbFile}
     * 
     * @param file
     * @param mode
     * @throws SmbException
     */
    public SmbRandomAccessFile ( SmbFile file, String mode ) throws SmbException {
        this(file, mode, SmbConstants.DEFAULT_SHARING, false);
    }


    /**
     * Instantiate a random access file from a {@link SmbFile}
     * 
     * @param file
     * @param mode
     * @throws SmbException
     */
    SmbRandomAccessFile ( SmbFile file, String mode, int sharing, boolean unsharedFile ) throws SmbException {
        this.file = file;
        this.sharing = sharing;
        this.unsharedFile = unsharedFile;

        try ( SmbTreeHandleInternal th = this.file.ensureTreeConnected() ) {
            if ( mode.equals("r") ) {
                this.openFlags = SmbConstants.O_CREAT | SmbConstants.O_RDONLY;
                this.access = SmbConstants.FILE_READ_DATA;
            }
            else if ( mode.equals("rw") ) {
                this.openFlags = SmbConstants.O_CREAT | SmbConstants.O_RDWR | SmbConstants.O_APPEND;
                this.write_andx_resp = new SmbComWriteAndXResponse(th.getConfig());
                this.options = WRITE_OPTIONS;
                this.access = SmbConstants.FILE_READ_DATA | SmbConstants.FILE_WRITE_DATA;
            }
            else {
                throw new IllegalArgumentException("Invalid mode");
            }

            try ( SmbFileHandle h = ensureOpen() ) {}
            this.readSize = th.getReceiveBufferSize() - 70;
            this.writeSize = th.getSendBufferSize() - 70;

            if ( th.hasCapability(SmbConstants.CAP_LARGE_READX) ) {
                this.largeReadX = true;
                this.readSize = Math.min(th.getConfig().getReceiveBufferSize() - 70, th.areSignaturesActive() ? 0xFFFF - 70 : 0xFFFFFF - 70);
            }

            // there seems to be a bug with some servers that causes corruption if using signatures + CAP_LARGE_WRITE
            if ( th.hasCapability(SmbConstants.CAP_LARGE_WRITEX) && !th.areSignaturesActive() ) {
                this.writeSize = Math.min(th.getConfig().getSendBufferSize() - 70, 0xFFFF - 70);
            }

            this.fp = 0L;
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    /**
     * @return
     * @throws SmbException
     */
    synchronized SmbFileHandleImpl ensureOpen () throws CIFSException {
        // ensure file is open
        if ( this.handle == null || !this.handle.isValid() ) {
            // one extra acquire to keep this open till the stream is released
            this.handle = this.file.openUnshared(this.openFlags, this.access, this.sharing, SmbConstants.ATTR_NORMAL, this.options).acquire();
            return this.handle;
        }
        return this.handle.acquire();
    }


    @Override
    public synchronized void close () throws SmbException {
        try {
            if ( this.handle != null ) {
                try {
                    this.handle.close();
                }
                catch ( CIFSException e ) {
                    throw SmbException.wrap(e);
                }
                this.handle = null;
            }
        }
        finally {
            this.file.clearAttributeCache();
            if ( this.unsharedFile ) {
                this.file.close();
            }
        }
    }


    @Override
    public int read () throws SmbException {
        if ( read(this.tmp, 0, 1) == -1 ) {
            return -1;
        }
        return this.tmp[ 0 ] & 0xFF;
    }


    @Override
    public int read ( byte b[] ) throws SmbException {
        return read(b, 0, b.length);
    }


    @Override
    public int read ( byte b[], int off, int len ) throws SmbException {
        if ( len <= 0 ) {
            return 0;
        }
        long start = this.fp;

        try ( SmbFileHandleImpl fh = ensureOpen();
              SmbTreeHandleImpl th = fh.getTree() ) {

            int r, n;
            SmbComReadAndXResponse response = new SmbComReadAndXResponse(th.getConfig(), b, off);
            do {
                r = len > this.readSize ? this.readSize : len;

                if ( th.isSMB2() ) {
                    Smb2ReadRequest request = new Smb2ReadRequest(th.getConfig(), fh.getFileId(), b, off);
                    request.setOffset(this.fp);
                    request.setReadLength(r);
                    request.setRemainingBytes(len - off);
                    try {
                        Smb2ReadResponse resp = th.send(request, RequestParam.NO_RETRY);
                        n = resp.getDataLength();
                    }
                    catch ( SmbException e ) {
                        if ( e.getNtStatus() == 0xC0000011 ) {
                            log.debug("Reached end of file", e);
                            n = -1;
                        }
                        else {
                            throw e;
                        }
                    }
                }
                else {
                    SmbComReadAndX request = new SmbComReadAndX(th.getConfig(), fh.getFid(), this.fp, r, null);
                    if ( this.largeReadX ) {
                        request.setMaxCount(r & 0xFFFF);
                        request.setOpenTimeout( ( r >> 16 ) & 0xFFFF);
                    }

                    try {
                        th.send(request, response, RequestParam.NO_RETRY);
                        n = response.getDataLength();
                    }
                    catch ( CIFSException e ) {
                        throw SmbException.wrap(e);
                    }
                }
                if ( n <= 0 ) {
                    return (int) ( ( this.fp - start ) > 0L ? this.fp - start : -1 );
                }
                this.fp += n;
                len -= n;
                off += n;
                response.adjustOffset(n);
            }
            while ( len > 0 && n == r );

            return (int) ( this.fp - start );
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public final void readFully ( byte b[] ) throws SmbException {
        readFully(b, 0, b.length);
    }


    @Override
    public final void readFully ( byte b[], int off, int len ) throws SmbException {
        int n = 0, count;

        do {
            count = this.read(b, off + n, len - n);
            if ( count < 0 )
                throw new SmbEndOfFileException();
            n += count;
        }
        while ( n < len );
    }


    @Override
    public int skipBytes ( int n ) throws SmbException {
        if ( n > 0 ) {
            this.fp += n;
            return n;
        }
        return 0;
    }


    @Override
    public void write ( int b ) throws SmbException {
        this.tmp[ 0 ] = (byte) b;
        write(this.tmp, 0, 1);
    }


    @Override
    public void write ( byte b[] ) throws SmbException {
        write(b, 0, b.length);
    }


    @Override
    public void write ( byte b[], int off, int len ) throws SmbException {
        if ( len <= 0 ) {
            return;
        }

        // ensure file is open
        try ( SmbFileHandleImpl fh = ensureOpen();
              SmbTreeHandleImpl th = fh.getTree() ) {
            int w;
            do {
                w = len > this.writeSize ? this.writeSize : len;
                long cnt;

                if ( th.isSMB2() ) {
                    Smb2WriteRequest request = new Smb2WriteRequest(th.getConfig(), fh.getFileId());
                    request.setOffset(this.fp);
                    request.setRemainingBytes(len - w - off);
                    request.setData(b, off, w);
                    Smb2WriteResponse resp = th.send(request, RequestParam.NO_RETRY);
                    cnt = resp.getCount();
                }
                else {
                    SmbComWriteAndX request = new SmbComWriteAndX(th.getConfig(), fh.getFid(), this.fp, len - w - off, b, off, w, null);
                    th.send(request, this.write_andx_resp, RequestParam.NO_RETRY);
                    cnt = this.write_andx_resp.getCount();
                }

                this.fp += cnt;
                len -= cnt;
                off += cnt;
            }
            while ( len > 0 );
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public long getFilePointer () {
        return this.fp;
    }


    @Override
    public void seek ( long pos ) {
        this.fp = pos;
    }


    @Override
    public long length () throws SmbException {
        return this.file.length();
    }


    @Override
    public void setLength ( long newLength ) throws SmbException {
        try ( SmbFileHandleImpl fh = ensureOpen();
              SmbTreeHandleImpl th = fh.getTree() ) {
            if ( th.isSMB2() ) {
                Smb2SetInfoRequest req = new Smb2SetInfoRequest(th.getConfig(), fh.getFileId());
                req.setFileInformation(new FileEndOfFileInformation(newLength));
                th.send(req, RequestParam.NO_RETRY);
            }
            else if ( th.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                th.send(
                    new Trans2SetFileInformation(th.getConfig(), fh.getFid(), new FileEndOfFileInformation(newLength)),
                    new Trans2SetFileInformationResponse(th.getConfig()),
                    RequestParam.NO_RETRY);
            }
            else {
                // this is the original, COM_WRITE allows truncation but no 64 bit offsets
                SmbComWriteResponse rsp = new SmbComWriteResponse(th.getConfig());
                th.send(
                    new SmbComWrite(th.getConfig(), fh.getFid(), (int) ( newLength & 0xFFFFFFFFL ), 0, this.tmp, 0, 0),
                    rsp,
                    RequestParam.NO_RETRY);
            }
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    @Override
    public final boolean readBoolean () throws SmbException {
        if ( ( read(this.tmp, 0, 1) ) < 0 ) {
            throw new SmbEndOfFileException();
        }
        return this.tmp[ 0 ] != (byte) 0x00;
    }


    @Override
    public final byte readByte () throws SmbException {
        if ( ( read(this.tmp, 0, 1) ) < 0 ) {
            throw new SmbEndOfFileException();
        }
        return this.tmp[ 0 ];
    }


    @Override
    public final int readUnsignedByte () throws SmbException {
        if ( ( read(this.tmp, 0, 1) ) < 0 ) {
            throw new SmbEndOfFileException();
        }
        return this.tmp[ 0 ] & 0xFF;
    }


    @Override
    public final short readShort () throws SmbException {
        if ( ( read(this.tmp, 0, 2) ) < 0 ) {
            throw new SmbEndOfFileException();
        }
        return Encdec.dec_uint16be(this.tmp, 0);
    }


    @Override
    public final int readUnsignedShort () throws SmbException {
        if ( ( read(this.tmp, 0, 2) ) < 0 ) {
            throw new SmbEndOfFileException();
        }
        return Encdec.dec_uint16be(this.tmp, 0) & 0xFFFF;
    }


    @Override
    public final char readChar () throws SmbException {
        if ( ( read(this.tmp, 0, 2) ) < 0 ) {
            throw new SmbEndOfFileException();
        }
        return (char) Encdec.dec_uint16be(this.tmp, 0);
    }


    @Override
    public final int readInt () throws SmbException {
        if ( ( read(this.tmp, 0, 4) ) < 0 ) {
            throw new SmbEndOfFileException();
        }
        return Encdec.dec_uint32be(this.tmp, 0);
    }


    @Override
    public final long readLong () throws SmbException {
        if ( ( read(this.tmp, 0, 8) ) < 0 ) {
            throw new SmbEndOfFileException();
        }
        return Encdec.dec_uint64be(this.tmp, 0);
    }


    @Override
    public final float readFloat () throws SmbException {
        if ( ( read(this.tmp, 0, 4) ) < 0 ) {
            throw new SmbEndOfFileException();
        }
        return Encdec.dec_floatbe(this.tmp, 0);
    }


    @Override
    public final double readDouble () throws SmbException {
        if ( ( read(this.tmp, 0, 8) ) < 0 ) {
            throw new SmbEndOfFileException();
        }
        return Encdec.dec_doublebe(this.tmp, 0);
    }


    @Override
    public final String readLine () throws SmbException {
        StringBuffer input = new StringBuffer();
        int c = -1;
        boolean eol = false;

        while ( !eol ) {
            switch ( c = read() ) {
            case -1:
            case '\n':
                eol = true;
                break;
            case '\r':
                eol = true;
                long cur = this.fp;
                if ( read() != '\n' ) {
                    this.fp = cur;
                }
                break;
            default:
                input.append((char) c);
                break;
            }
        }

        if ( ( c == -1 ) && ( input.length() == 0 ) ) {
            return null;
        }

        return input.toString();
    }


    @Override
    public final String readUTF () throws SmbException {
        int size = readUnsignedShort();
        byte[] b = new byte[size];
        read(b, 0, size);
        try {
            return Encdec.dec_utf8(b, 0, size);
        }
        catch ( IOException ioe ) {
            throw new SmbException("", ioe);
        }
    }


    @Override
    public final void writeBoolean ( boolean v ) throws SmbException {
        this.tmp[ 0 ] = (byte) ( v ? 1 : 0 );
        write(this.tmp, 0, 1);
    }


    @Override
    public final void writeByte ( int v ) throws SmbException {
        this.tmp[ 0 ] = (byte) v;
        write(this.tmp, 0, 1);
    }


    @Override
    public final void writeShort ( int v ) throws SmbException {
        Encdec.enc_uint16be((short) v, this.tmp, 0);
        write(this.tmp, 0, 2);
    }


    @Override
    public final void writeChar ( int v ) throws SmbException {
        Encdec.enc_uint16be((short) v, this.tmp, 0);
        write(this.tmp, 0, 2);
    }


    @Override
    public final void writeInt ( int v ) throws SmbException {
        Encdec.enc_uint32be(v, this.tmp, 0);
        write(this.tmp, 0, 4);
    }


    @Override
    public final void writeLong ( long v ) throws SmbException {
        Encdec.enc_uint64be(v, this.tmp, 0);
        write(this.tmp, 0, 8);
    }


    @Override
    public final void writeFloat ( float v ) throws SmbException {
        Encdec.enc_floatbe(v, this.tmp, 0);
        write(this.tmp, 0, 4);
    }


    @Override
    public final void writeDouble ( double v ) throws SmbException {
        Encdec.enc_doublebe(v, this.tmp, 0);
        write(this.tmp, 0, 8);
    }


    @Override
    public final void writeBytes ( String s ) throws SmbException {
        byte[] b = s.getBytes();
        write(b, 0, b.length);
    }


    @Override
    public final void writeChars ( String s ) throws SmbException {
        int clen = s.length();
        int blen = 2 * clen;
        byte[] b = new byte[blen];
        char[] c = new char[clen];
        s.getChars(0, clen, c, 0);
        for ( int i = 0, j = 0; i < clen; i++ ) {
            b[ j++ ] = (byte) ( c[ i ] >>> 8 );
            b[ j++ ] = (byte) ( c[ i ] >>> 0 );
        }
        write(b, 0, blen);
    }


    @Override
    public final void writeUTF ( String str ) throws SmbException {
        int len = str.length();
        int ch, size = 0;
        byte[] dst;

        for ( int i = 0; i < len; i++ ) {
            ch = str.charAt(i);
            size += ch > 0x07F ? ( ch > 0x7FF ? 3 : 2 ) : 1;
        }
        dst = new byte[size];
        writeShort(size);
        Encdec.enc_utf8(str, dst, 0, size);
        write(dst, 0, size);
    }

}
