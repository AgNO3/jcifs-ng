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
package jcifs.internal.smb2;


/**
 * @author mbechler
 *
 */
public final class Smb2Constants {

    /**
     * 
     */
    private Smb2Constants () {}

    /**
     * 
     */
    public static final int SMB2_HEADER_LENGTH = 64;

    /**
     * 
     */
    public static final int SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001;

    /**
     * 
     */
    public static final int SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002;

    /**
     * 
     */
    public static final int SMB2_DIALECT_0202 = 0x0202;

    /**
     * 
     */
    public static final int SMB2_DIALECT_0210 = 0x0210;

    /**
     * 
     */
    public static final int SMB2_DIALECT_0300 = 0x0300;

    /**
     * 
     */
    public static final int SMB2_DIALECT_0302 = 0x0302;

    /**
     * 
     */
    public static final int SMB2_DIALECT_0311 = 0x0311;

    /**
     * 
     */
    public static final int SMB2_DIALECT_ANY = 0x02FF;

    /**
     * 
     */
    public static final int SMB2_GLOBAL_CAP_DFS = 0x1;

    /**
     * 
     */
    public static final int SMB2_GLOBAL_CAP_LEASING = 0x2;

    /**
     * 
     */
    public static final int SMB2_GLOBAL_CAP_LARGE_MTU = 0x4;

    /**
     * 
     */
    public static final int SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x8;

    /**
     * 
     */
    public static final int SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x10;

    /**
     * 
     */
    public static final int SMB2_GLOBAL_CAP_DIRECTORY_LEASING = 0x20;

    /**
     * 
     */
    public static final int SMB2_GLOBAL_CAP_ENCRYPTION = 0x40;

    /**
     * 
     */
    public static final byte SMB2_0_INFO_FILE = 1;

    /**
     * 
     */
    public static final byte SMB2_0_INFO_FILESYSTEM = 2;

    /**
     * 
     */
    public static final byte SMB2_0_INFO_SECURITY = 3;

    /**
     * 
     */
    public static final byte SMB2_0_INFO_QUOTA = 4;

    /**
     * 
     */
    public static final byte[] UNSPECIFIED_FILEID = new byte[] {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    /**
     * 
     */
    public static final int UNSPECIFIED_TREEID = 0xFFFFFFFF;

    /**
     * 
     */
    public static final long UNSPECIFIED_SESSIONID = 0xFFFFFFFFFFFFFFFFL;
}
