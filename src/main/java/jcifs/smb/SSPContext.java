/*
 * © 2016 AgNO3 Gmbh & Co. KG
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


import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import jcifs.CIFSException;


/**
 * @author mbechler
 *
 */
public interface SSPContext {

    /**
     * @return the signing key for the session
     * 
     * @throws CIFSException
     */
    byte[] getSigningKey () throws CIFSException;


    /**
     * @return whether the context is established
     */
    boolean isEstablished ();


    /**
     * @param token
     * @param off
     * @param len
     * @return result token
     * @throws SmbException
     * @throws CIFSException
     */
    byte[] initSecContext ( byte[] token, int off, int len ) throws CIFSException;


    /**
     * @return the name of the remote endpoint
     */
    String getNetbiosName ();


    /**
     * @throws CIFSException
     */
    void dispose () throws CIFSException;


    /**
     * @param mechanism
     * @return whether the specified mechanism is supported
     */
    boolean isSupported ( ASN1ObjectIdentifier mechanism );


    /**
     * @param selectedMech
     * @return whether the specified mechanism is preferred
     */
    boolean isPreferredMech ( ASN1ObjectIdentifier selectedMech );


    /**
     * @return context flags
     */
    int getFlags ();


    /**
     * @return array of supported mechanism OIDs
     */
    ASN1ObjectIdentifier[] getSupportedMechs ();


    /**
     * 
     * @return whether this mechanisms supports integrity
     */
    boolean supportsIntegrity ();


    /**
     * @param data
     * @return MIC
     * @throws CIFSException
     */
    byte[] calculateMIC ( byte[] data ) throws CIFSException;


    /**
     * @param data
     * @param mic
     * @throws CIFSException
     */
    void verifyMIC ( byte[] data, byte[] mic ) throws CIFSException;


    /**
     * @return whether MIC can be used
     */
    boolean isMICAvailable ();

}
