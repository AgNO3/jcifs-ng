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
package jcifs.internal.dtyp;


import jcifs.Decodable;


/**
 * @author mbechler
 *
 */
public interface SecurityInfo extends Decodable {

    /**
     * 
     */
    public static final int OWNER_SECURITY_INFO = 0x1;

    /**
     * 
     */
    public static final int GROUP_SECURITY_INFO = 0x2;

    /**
     * 
     */
    public static final int DACL_SECURITY_INFO = 0x4;

    /**
     * 
     */
    public static final int SACL_SECURITY_INFO = 0x8;

    /**
     * 
     */
    public static final int LABEL_SECURITY_INFO = 0x10;

    /**
     * 
     */
    public static final int ATTRIBUTE_SECURITY_INFO = 0x20;

    /**
     * 
     */
    public static final int SCOPE_SECURITY_INFO = 0x40;

    /**
     * 
     */
    public static final int BACKUP_SECURITY_INFO = 0x1000;
}
