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
package jcifs.internal;


/**
 * @author mbechler
 *
 */
public interface SMBSigningDigest {

    /**
     * Performs MAC signing of the SMB. This is done as follows.
     * The signature field of the SMB is overwritten with the sequence number;
     * The MD5 digest of the MAC signing key + the entire SMB is taken;
     * The first 8 bytes of this are placed in the signature field.
     *
     * @param data
     *            The data.
     * @param offset
     *            The starting offset at which the SMB header begins.
     * @param length
     *            The length of the SMB data starting at offset.
     * @param request
     *            request message
     * @param response
     *            response message
     */
    void sign ( byte[] data, int offset, int length, CommonServerMessageBlock request, CommonServerMessageBlock response );


    /**
     * Performs MAC signature verification. This calculates the signature
     * of the SMB and compares it to the signature field on the SMB itself.
     *
     * @param data
     *            The data.
     * @param offset
     *            The starting offset at which the SMB header begins.
     * @param length
     * @param extraPad
     *            extra padding to include in signature
     * @param msg
     *            The message to verify
     * @return whether verification was unsuccessful
     */
    boolean verify ( byte[] data, int offset, int length, int extraPad, CommonServerMessageBlock msg );

}