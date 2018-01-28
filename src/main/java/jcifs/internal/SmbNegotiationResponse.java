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


import jcifs.CIFSContext;
import jcifs.DialectVersion;
import jcifs.util.transport.Response;


/**
 * @author mbechler
 *
 */
public interface SmbNegotiationResponse extends CommonServerMessageBlock, Response {

    /**
     * 
     * @param cifsContext
     * @param singingEnforced
     * @param request
     * @return whether the protocol negotiation was successful
     */
    boolean isValid ( CIFSContext cifsContext, SmbNegotiationRequest request );


    /**
     * 
     * @return selected dialect
     */
    DialectVersion getSelectedDialect ();


    /**
     * 
     * @return whether the server has singing enabled
     */
    boolean isSigningEnabled ();


    /**
     * 
     * @return whether the server requires signing
     */
    boolean isSigningRequired ();


    /**
     * @return whether the server supports DFS
     */
    boolean isDFSSupported ();


    /**
     * @param request
     */
    void setupRequest ( CommonServerMessageBlock request );


    /**
     * @param resp
     */
    void setupResponse ( Response resp );


    /**
     * @return whether signing has been negotiated
     */
    boolean isSigningNegotiated ();


    /**
     * @param cap
     * @return whether capability is negotiated
     */
    boolean haveCapabilitiy ( int cap );


    /**
     * @return the send buffer size
     */
    int getSendBufferSize ();


    /**
     * @return the receive buffer size
     */
    int getReceiveBufferSize ();


    /**
     * 
     * @return the transaction buffer size
     */
    int getTransactionBufferSize ();


    /**
     * 
     * @return number of initial credits the server grants
     */
    int getInitialCredits ();


    /**
     * @param tc
     * @param forceSigning
     * @return whether a connection can be reused for this config
     */
    boolean canReuse ( CIFSContext tc, boolean forceSigning );

}
