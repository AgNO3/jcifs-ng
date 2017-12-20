/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package jcifs.ntlmssp;


import java.io.IOException;

import jcifs.SmbConstants;


/**
 * Abstract superclass for all NTLMSSP messages.
 */
public abstract class NtlmMessage implements NtlmFlags {

    /**
     * The NTLMSSP "preamble".
     */
    protected static final byte[] NTLMSSP_SIGNATURE = new byte[] {
        (byte) 'N', (byte) 'T', (byte) 'L', (byte) 'M', (byte) 'S', (byte) 'S', (byte) 'P', (byte) 0
    };

    /**
     * NTLM version
     */
    protected static final byte[] NTLMSSP_VERSION = new byte[] {
        6, 1, 0, 0, 0, 0, 0, 15
    };

    protected static final int NTLMSSP_TYPE1 = 0x1;
    protected static final int NTLMSSP_TYPE2 = 0x2;
    protected static final int NTLMSSP_TYPE3 = 0x3;

    private static final String OEM_ENCODING = SmbConstants.DEFAULT_OEM_ENCODING;
    protected static final String UNI_ENCODING = "UTF-16LE";

    private int flags;


    /**
     * Returns the flags currently in use for this message.
     *
     * @return An <code>int</code> containing the flags in use for this
     *         message.
     */
    public int getFlags () {
        return this.flags;
    }


    /**
     * Sets the flags for this message.
     *
     * @param flags
     *            The flags for this message.
     */
    public void setFlags ( int flags ) {
        this.flags = flags;
    }


    /**
     * Returns the status of the specified flag.
     *
     * @param flag
     *            The flag to test (i.e., <code>NTLMSSP_NEGOTIATE_OEM</code>).
     * @return A <code>boolean</code> indicating whether the flag is set.
     */
    public boolean getFlag ( int flag ) {
        return ( getFlags() & flag ) != 0;
    }


    /**
     * Sets or clears the specified flag.
     * 
     * @param flag
     *            The flag to set/clear (i.e.,
     *            <code>NTLMSSP_NEGOTIATE_OEM</code>).
     * @param value
     *            Indicates whether to set (<code>true</code>) or
     *            clear (<code>false</code>) the specified flag.
     */
    public void setFlag ( int flag, boolean value ) {
        setFlags(value ? ( getFlags() | flag ) : ( getFlags() & ( 0xffffffff ^ flag ) ));
    }


    static int readULong ( byte[] src, int index ) {
        return ( src[ index ] & 0xff ) | ( ( src[ index + 1 ] & 0xff ) << 8 ) | ( ( src[ index + 2 ] & 0xff ) << 16 )
                | ( ( src[ index + 3 ] & 0xff ) << 24 );
    }


    static int readUShort ( byte[] src, int index ) {
        return ( src[ index ] & 0xff ) | ( ( src[ index + 1 ] & 0xff ) << 8 );
    }


    static byte[] readSecurityBuffer ( byte[] src, int index ) {
        int length = readUShort(src, index);
        int offset = readULong(src, index + 4);
        byte[] buffer = new byte[length];
        System.arraycopy(src, offset, buffer, 0, length);
        return buffer;
    }


    static void writeULong ( byte[] dest, int offset, int ulong ) {
        dest[ offset ] = (byte) ( ulong & 0xff );
        dest[ offset + 1 ] = (byte) ( ulong >> 8 & 0xff );
        dest[ offset + 2 ] = (byte) ( ulong >> 16 & 0xff );
        dest[ offset + 3 ] = (byte) ( ulong >> 24 & 0xff );
    }


    static void writeUShort ( byte[] dest, int offset, int ushort ) {
        dest[ offset ] = (byte) ( ushort & 0xff );
        dest[ offset + 1 ] = (byte) ( ushort >> 8 & 0xff );
    }


    static int writeSecurityBuffer ( byte[] dest, int offset, byte[] src ) {
        int length = ( src != null ) ? src.length : 0;
        if ( length == 0 ) {
            return offset + 4;
        }
        writeUShort(dest, offset, length);
        writeUShort(dest, offset + 2, length);
        return offset + 4;
    }


    static int writeSecurityBufferContent ( byte[] dest, int pos, int off, byte[] src ) {
        writeULong(dest, off, pos);
        if ( src != null && src.length > 0 ) {
            System.arraycopy(src, 0, dest, pos, src.length);
            return src.length;
        }
        return 0;
    }


    static String getOEMEncoding () {
        return OEM_ENCODING;
    }


    /**
     * Returns the raw byte representation of this message.
     *
     * @return A <code>byte[]</code> containing the raw message material.
     * @throws IOException
     */
    public abstract byte[] toByteArray () throws IOException;

}
