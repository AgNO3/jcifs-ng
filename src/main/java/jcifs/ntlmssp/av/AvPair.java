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
package jcifs.ntlmssp.av;


/**
 * @author mbechler
 *
 */
public class AvPair {

    /**
     * EOL type
     */
    public static final int MsvAvEOL = 0x0;

    /**
     * Flags type
     */
    public static final int MsvAvFlags = 0x6;

    /**
     * Timestamp type
     */
    public static final int MsvAvTimestamp = 0x7;

    /**
     * Single host type
     */
    public static final int MsvAvSingleHost = 0x08;

    /**
     * Target name type
     */
    public static final int MsvAvTargetName = 0x09;

    /**
     * Channel bindings type
     */
    public static final int MsvAvChannelBindings = 0x0A;

    private final int type;
    private final byte[] raw;


    /**
     * @param type
     * @param raw
     */
    public AvPair ( int type, byte[] raw ) {
        this.type = type;
        this.raw = raw;
    }


    /**
     * @return the type
     */
    public final int getType () {
        return this.type;
    }


    /**
     * @return the raw
     */
    public final byte[] getRaw () {
        return this.raw;
    }

}
