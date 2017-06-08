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
package jcifs.internal.fscc;


import jcifs.Decodable;
import jcifs.Encodable;


/**
 * @author mbechler
 *
 */
public interface FileInformation extends Decodable, Encodable {

    // information levels

    /**
     * 
     */
    public static final byte FILE_ENDOFFILE_INFO = 20;

    /**
     * 
     */
    public static final byte FILE_BASIC_INFO = 0x4;
    /**
     * 
     */
    public static final byte FILE_STANDARD_INFO = 0x5;

    /**
     * 
     */
    public static final byte FILE_INTERNAL_INFO = 0x6;

    /**
     * 
     */
    public static final byte FILE_RENAME_INFO = 10;


    /**
     * 
     * @return the file information class
     */
    byte getFileInformationLevel ();
}
