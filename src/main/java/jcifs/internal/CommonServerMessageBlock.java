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


import jcifs.util.transport.Message;


/**
 * @author mbechler
 *
 */
public interface CommonServerMessageBlock extends Message {

    /**
     * Decode message data from the given byte array
     * 
     * @param buffer
     * @param bufferIndex
     * @return message length
     * @throws SMBProtocolDecodingException
     */
    int decode ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException;


    /**
     * @param dst
     * @param dstIndex
     * @return message length
     */
    int encode ( byte[] dst, int dstIndex );


    /**
     * @param digest
     */
    void setDigest ( SMBSigningDigest digest );


    /**
     * @return the signing digest
     */
    SMBSigningDigest getDigest ();


    /**
     * @return the associated response
     */
    CommonServerMessageBlockResponse getResponse ();


    /**
     * 
     * @param msg
     */
    void setResponse ( CommonServerMessageBlockResponse msg );


    /**
     * 
     * @return the message id
     */
    long getMid ();


    /**
     * @param mid
     */
    void setMid ( long mid );


    /**
     * @return the command
     */
    int getCommand ();


    /**
     * @param command
     */
    void setCommand ( int command );


    /**
     * @param uid
     */
    void setUid ( int uid );


    /**
     * @param extendedSecurity
     */
    void setExtendedSecurity ( boolean extendedSecurity );


    /**
     * @param sessionId
     */
    void setSessionId ( long sessionId );


    /**
     * 
     */
    void reset ();

}
