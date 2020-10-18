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
package jcifs;


import java.net.URLStreamHandler;


/**
 * Encapsulation of client context
 * 
 * 
 * A context holds the client configuration, shared services as well as the active credentials.
 * 
 * Usually you will want to create one context per client configuration and then
 * multiple sub-contexts using different credentials (if necessary).
 * 
 * {@link #withDefaultCredentials()}, {@link #withAnonymousCredentials()}, {@link #withCredentials(Credentials)}
 * allow to create such sub-contexts.
 * 
 * 
 * Implementors of this interface should extend {@link jcifs.context.BaseContext} or
 * {@link jcifs.context.CIFSContextWrapper} to get forward compatibility.
 * 
 * @author mbechler
 *
 */
public interface CIFSContext {

    /**
     * Get a resource
     * 
     * @param url
     * @return the SMB resource at the specified location
     * @throws CIFSException
     */
    SmbResource get ( String url ) throws CIFSException;


    /**
     * Get a pipe resource
     * 
     * @param url
     * @param pipeType
     *            the type of the pipe
     * @return the SMB pipe resource at the specified location
     * @throws CIFSException
     */
    SmbPipeResource getPipe ( String url, int pipeType ) throws CIFSException;


    /**
     * 
     * @return whether any connection was still in use
     * @throws CIFSException
     */
    boolean close () throws CIFSException;


    /**
     * 
     * @return the active configuration
     */
    Configuration getConfig ();


    /**
     * @return the name server client
     */
    NameServiceClient getNameServiceClient ();


    /**
     * @return the buffer cache
     */
    BufferCache getBufferCache ();


    /**
     * @return the transport pool
     */
    SmbTransportPool getTransportPool ();


    /**
     * @return the DFS instance for this context
     */
    DfsResolver getDfs ();


    /**
     * @return the SID resolver for this context
     */
    SidResolver getSIDResolver ();


    /**
     * 
     * @return the used credentials
     */
    Credentials getCredentials ();


    /**
     * @return an URL handler using this context
     */
    URLStreamHandler getUrlHandler ();


    /**
     * @return whether default credentials are available
     */
    boolean hasDefaultCredentials ();


    /**
     * @return a child context using the configured default credentials
     */
    CIFSContext withDefaultCredentials ();


    /**
     * @return a child context using anonymous credentials
     */
    CIFSContext withAnonymousCredentials ();


    /**
     * 
     * @return a child context using guest credentials
     */
    CIFSContext withGuestCrendentials ();


    /**
     * 
     * @param creds
     * @return a child context using using the given credentials
     */
    CIFSContext withCredentials ( Credentials creds );


    /**
     * @param locationHint
     * @param error
     * @return whether new credentials are obtained
     */
    boolean renewCredentials ( String locationHint, Throwable error );

}
