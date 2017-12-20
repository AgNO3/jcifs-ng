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


import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;


/**
 * @author mbechler
 *
 */
public class AvTargetName extends AvPair {

    /**
     * 
     */
    private static final Charset UTF16LE = StandardCharsets.UTF_16LE;


    /**
     * @param raw
     */
    public AvTargetName ( byte[] raw ) {
        super(AvPair.MsvAvTargetName, raw);
    }


    /**
     * 
     * @param targetName
     */
    public AvTargetName ( String targetName ) {
        this(encode(targetName));
    }


    /**
     * 
     * @return the target name
     */
    public String getTargetName () {
        return new String(getRaw(), UTF16LE);
    }


    /**
     * @param targetName
     * @return
     */
    private static byte[] encode ( String targetName ) {
        return targetName.getBytes(UTF16LE);
    }

}
