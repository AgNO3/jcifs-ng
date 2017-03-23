/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Christopher R. Hertel" <jcifs at samba dot org>
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

package jcifs.netbios;


import jcifs.Configuration;
import jcifs.NetbiosName;
import jcifs.util.Hexdump;
import jcifs.util.Strings;


/**
 * 
 * 
 */
public class Name implements NetbiosName {

    private static final int TYPE_OFFSET = 31;
    private static final int SCOPE_OFFSET = 33;

    /**
     * Name
     */
    public String name;
    /**
     * Scope id
     */
    public String scope;
    /**
     * Type
     */
    public int hexCode;
    int srcHashCode; /*
                      * srcHashCode must be set by name resolution
                      * routines before entry into addressCache
                      */
    private Configuration config;


    Name ( Configuration cfg ) {
        this.config = cfg;
    }


    /**
     * @return the name
     */
    @Override
    public String getName () {
        return this.name;
    }


    /**
     * @return scope id
     */
    @Override
    public String getScope () {
        return this.scope;
    }


    /**
     * 
     * @return the name type
     */
    @Override
    public int getNameType () {
        return this.hexCode;
    }


    /**
     * 
     * @param cfg
     * @param name
     * @param hexCode
     * @param scope
     */
    public Name ( Configuration cfg, String name, int hexCode, String scope ) {
        this.config = cfg;
        if ( name.length() > 15 ) {
            name = name.substring(0, 15);
        }
        this.name = name.toUpperCase();
        this.hexCode = hexCode;
        this.scope = scope != null && scope.length() > 0 ? scope : cfg.getNetbiosScope();
        this.srcHashCode = 0;
    }


    /**
     * @param cfg
     * @param name
     */
    public Name ( Configuration cfg, NetbiosName name ) {
        this.config = cfg;
        this.name = name.getName();
        this.hexCode = name.getNameType();
        this.scope = name.getScope();
        if ( name instanceof Name ) {
            this.srcHashCode = ( (Name) name ).srcHashCode;
        }
    }


    /**
     * 
     * @return whether this is the unknown address
     */
    public boolean isUnknown () {
        return "0.0.0.0".equals(this.name) && this.hexCode == 0 && this.scope == null;
    }


    int writeWireFormat ( byte[] dst, int dstIndex ) {
        // write 0x20 in first byte
        dst[ dstIndex ] = 0x20;

        byte tmp[] = Strings.getOEMBytes(this.name, this.config);
        int i;
        for ( i = 0; i < tmp.length; i++ ) {
            dst[ dstIndex + ( 2 * i + 1 ) ] = (byte) ( ( ( tmp[ i ] & 0xF0 ) >> 4 ) + 0x41 );
            dst[ dstIndex + ( 2 * i + 2 ) ] = (byte) ( ( tmp[ i ] & 0x0F ) + 0x41 );
        }
        for ( ; i < 15; i++ ) {
            dst[ dstIndex + ( 2 * i + 1 ) ] = (byte) 0x43;
            dst[ dstIndex + ( 2 * i + 2 ) ] = (byte) 0x41;
        }
        dst[ dstIndex + TYPE_OFFSET ] = (byte) ( ( ( this.hexCode & 0xF0 ) >> 4 ) + 0x41 );
        dst[ dstIndex + TYPE_OFFSET + 1 ] = (byte) ( ( this.hexCode & 0x0F ) + 0x41 );
        return SCOPE_OFFSET + writeScopeWireFormat(dst, dstIndex + SCOPE_OFFSET);
    }


    int readWireFormat ( byte[] src, int srcIndex ) {

        byte tmp[] = new byte[SCOPE_OFFSET];
        int length = 15;
        for ( int i = 0; i < 15; i++ ) {
            tmp[ i ] = (byte) ( ( ( src[ srcIndex + ( 2 * i + 1 ) ] & 0xFF ) - 0x41 ) << 4 );
            tmp[ i ] |= (byte) ( ( ( src[ srcIndex + ( 2 * i + 2 ) ] & 0xFF ) - 0x41 ) & 0x0F );
            if ( tmp[ i ] != (byte) ' ' ) {
                length = i + 1;
            }
        }
        this.name = Strings.fromOEMBytes(tmp, 0, length, this.config);
        this.hexCode = ( ( src[ srcIndex + TYPE_OFFSET ] & 0xFF ) - 0x41 ) << 4;
        this.hexCode |= ( ( src[ srcIndex + TYPE_OFFSET + 1 ] & 0xFF ) - 0x41 ) & 0x0F;
        return SCOPE_OFFSET + readScopeWireFormat(src, srcIndex + SCOPE_OFFSET);
    }


    int writeScopeWireFormat ( byte[] dst, int dstIndex ) {
        if ( this.scope == null ) {
            dst[ dstIndex ] = (byte) 0x00;
            return 1;
        }

        // copy new scope in
        dst[ dstIndex++ ] = (byte) '.';
        System.arraycopy(Strings.getOEMBytes(this.scope, this.config), 0, dst, dstIndex, this.scope.length());
        dstIndex += this.scope.length();

        dst[ dstIndex++ ] = (byte) 0x00;

        // now go over scope backwards converting '.' to label length

        int i = dstIndex - 2;
        int e = i - this.scope.length();
        int c = 0;

        do {
            if ( dst[ i ] == '.' ) {
                dst[ i ] = (byte) c;
                c = 0;
            }
            else {
                c++;
            }
        }
        while ( i-- > e );
        return this.scope.length() + 2;
    }


    int readScopeWireFormat ( byte[] src, int srcIndex ) {
        int start = srcIndex;
        int n;
        StringBuffer sb;

        if ( ( n = src[ srcIndex++ ] & 0xFF ) == 0 ) {
            this.scope = null;
            return 1;
        }

        sb = new StringBuffer(Strings.fromOEMBytes(src, srcIndex, n, this.config));
        srcIndex += n;
        while ( ( n = src[ srcIndex++ ] & 0xFF ) != 0 ) {
            sb.append('.').append(Strings.fromOEMBytes(src, srcIndex, n, this.config));
            srcIndex += n;
        }
        this.scope = sb.toString();

        return srcIndex - start;
    }


    @Override
    public int hashCode () {
        int result;

        result = this.name.hashCode();
        result += 65599 * this.hexCode;
        result += 65599 * this.srcHashCode; /*
                                             * hashCode is different depending
                                             * on where it came from
                                             */
        if ( this.scope != null && this.scope.length() != 0 ) {
            result += this.scope.hashCode();
        }
        return result;
    }


    @Override
    public boolean equals ( Object obj ) {
        Name n;

        if ( ! ( obj instanceof Name ) ) {
            return false;
        }
        n = (Name) obj;
        if ( this.scope == null && n.scope == null ) {
            return this.name.equals(n.name) && this.hexCode == n.hexCode;
        }
        return this.name.equals(n.name) && this.hexCode == n.hexCode && this.scope.equals(n.scope);
    }


    @Override
    public String toString () {
        StringBuffer sb = new StringBuffer();
        String n = this.name;

        // fix MSBROWSE name
        if ( n == null ) {
            n = "null";
        }
        else if ( n.charAt(0) == 0x01 ) {
            char c[] = n.toCharArray();
            c[ 0 ] = '.';
            c[ 1 ] = '.';
            c[ 14 ] = '.';
            n = new String(c);
        }

        sb.append(n).append("<").append(Hexdump.toHexString(this.hexCode, 2)).append(">");
        if ( this.scope != null ) {
            sb.append(".").append(this.scope);
        }
        return sb.toString();
    }
}
