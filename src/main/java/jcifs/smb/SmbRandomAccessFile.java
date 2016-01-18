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


import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.net.MalformedURLException;

import jcifs.CIFSContext;
import jcifs.SmbConstants;
import jcifs.util.Encdec;


public class SmbRandomAccessFile implements DataOutput, DataInput {

    private static final int WRITE_OPTIONS = 0x0842;

    private SmbFile file;
    private long fp;
    private int openFlags, access = 0, readSize, writeSize, options = 0;
    private byte[] tmp = new byte[8];
    private SmbComWriteAndXResponse write_andx_resp = null;


    /**
     * This constructor is used to instance a SmbRandomAccessFile object with
     * a SmbTransportContext
     * 
     * @param url
     * @param mode
     * @param shareAccess
     * @param tc
     * @throws SmbException
     * @throws MalformedURLException
     * @throws UnknownHostException
     */
    public SmbRandomAccessFile ( String url, String mode, int shareAccess, CIFSContext tc ) throws SmbException, MalformedURLException {
        this(new SmbFile(url, tc, shareAccess), mode);
    }


    public SmbRandomAccessFile ( SmbFile file, String mode ) throws SmbException {
        this.file = file;
        if ( mode.equals("r") ) {
            this.openFlags = SmbFile.O_CREAT | SmbFile.O_RDONLY;
        }
        else if ( mode.equals("rw") ) {
            this.openFlags = SmbFile.O_CREAT | SmbFile.O_RDWR | SmbFile.O_APPEND;
            this.write_andx_resp = new SmbComWriteAndXResponse(getSession().getConfig());
            this.options = WRITE_OPTIONS;
            this.access = SmbConstants.FILE_READ_DATA | SmbConstants.FILE_WRITE_DATA;
        }
        else {
            throw new IllegalArgumentException("Invalid mode");
        }
        file.open(this.openFlags, this.access, SmbFile.ATTR_NORMAL, this.options);
        this.readSize = file.tree.session.getTransport().rcv_buf_size - 70;
        this.writeSize = file.tree.session.getTransport().snd_buf_size - 70;

        boolean isSignatureActive = file.tree.session.getTransport().server.signaturesRequired
                || ( file.tree.session.getTransport().server.signaturesEnabled && file.getTransportContext().getConfig().isSigningPreferred() );
        if ( file.tree.session.getTransport().hasCapability(SmbConstants.CAP_LARGE_READX) && !isSignatureActive ) {
            this.readSize = Math.min(file.getTransportContext().getConfig().getRecieveBufferSize() - 70, 0xFFFF - 70);
        }

        if ( file.tree.session.getTransport().hasCapability(SmbConstants.CAP_LARGE_WRITEX) && !isSignatureActive ) {
            this.writeSize = Math.min(file.getTransportContext().getConfig().getSendBufferSize() - 70, 0xFFFF - 70);
        }

        this.fp = 0L;
    }


    private SmbSession getSession () {
        return this.file.tree.session;
    }


    public int read () throws SmbException {
        if ( read(this.tmp, 0, 1) == -1 ) {
            return -1;
        }
        return this.tmp[ 0 ] & 0xFF;
    }


    public int read ( byte b[] ) throws SmbException {
        return read(b, 0, b.length);
    }


    public int read ( byte b[], int off, int len ) throws SmbException {
        if ( len <= 0 ) {
            return 0;
        }
        long start = this.fp;

        // ensure file is open
        if ( this.file.isOpen() == false ) {
            this.file.open(this.openFlags, 0, SmbFile.ATTR_NORMAL, this.options);
        }

        int r, n;
        SmbComReadAndXResponse response = new SmbComReadAndXResponse(getSession().getConfig(), b, off);
        do {
            r = len > this.readSize ? this.readSize : len;
            this.file.send(new SmbComReadAndX(getSession().getConfig(), this.file.fid, this.fp, r, null), response);
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
                throw new SmbException("EOF");
            n += count;
            this.fp += count;
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
        if ( this.file.isOpen() == false ) {
            this.file.open(this.openFlags, 0, SmbFile.ATTR_NORMAL, this.options);
        }

        int w;
        do {
            w = len > this.writeSize ? this.writeSize : len;
            this.file.send(new SmbComWriteAndX(getSession().getConfig(), this.file.fid, this.fp, len - w, b, off, w, null), this.write_andx_resp);
            this.fp += this.write_andx_resp.count;
            len -= this.write_andx_resp.count;
            off += this.write_andx_resp.count;
        }
        while ( len > 0 );
    }


    public long getFilePointer () {
        return this.fp;
    }


    public void seek ( long pos ) {
        this.fp = pos;
    }


    public long length () throws SmbException {
        return this.file.length();
    }


    public void setLength ( long newLength ) throws SmbException {
        // ensure file is open
        if ( this.file.isOpen() == false ) {
            this.file.open(this.openFlags, 0, SmbFile.ATTR_NORMAL, this.options);
        }
        SmbComWriteResponse rsp = new SmbComWriteResponse(getSession().getConfig());
        this.file.send(new SmbComWrite(getSession().getConfig(), this.file.fid, (int) ( newLength & 0xFFFFFFFFL ), 0, this.tmp, 0, 0), rsp);
    }


    public void close () throws SmbException {
        this.file.close();
    }


    @Override
    public final boolean readBoolean () throws SmbException {
        if ( ( read(this.tmp, 0, 1) ) < 0 ) {
            throw new SmbException("EOF");
        }
        return this.tmp[ 0 ] != (byte) 0x00;
    }


    @Override
    public final byte readByte () throws SmbException {
        if ( ( read(this.tmp, 0, 1) ) < 0 ) {
            throw new SmbException("EOF");
        }
        return this.tmp[ 0 ];
    }


    @Override
    public final int readUnsignedByte () throws SmbException {
        if ( ( read(this.tmp, 0, 1) ) < 0 ) {
            throw new SmbException("EOF");
        }
        return this.tmp[ 0 ] & 0xFF;
    }


    @Override
    public final short readShort () throws SmbException {
        if ( ( read(this.tmp, 0, 2) ) < 0 ) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_uint16be(this.tmp, 0);
    }


    @Override
    public final int readUnsignedShort () throws SmbException {
        if ( ( read(this.tmp, 0, 2) ) < 0 ) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_uint16be(this.tmp, 0) & 0xFFFF;
    }


    @Override
    public final char readChar () throws SmbException {
        if ( ( read(this.tmp, 0, 2) ) < 0 ) {
            throw new SmbException("EOF");
        }
        return (char) Encdec.dec_uint16be(this.tmp, 0);
    }


    @Override
    public final int readInt () throws SmbException {
        if ( ( read(this.tmp, 0, 4) ) < 0 ) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_uint32be(this.tmp, 0);
    }


    @Override
    public final long readLong () throws SmbException {
        if ( ( read(this.tmp, 0, 8) ) < 0 ) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_uint64be(this.tmp, 0);
    }


    @Override
    public final float readFloat () throws SmbException {
        if ( ( read(this.tmp, 0, 4) ) < 0 ) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_floatbe(this.tmp, 0);
    }


    @Override
    public final double readDouble () throws SmbException {
        if ( ( read(this.tmp, 0, 8) ) < 0 ) {
            throw new SmbException("EOF");
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
