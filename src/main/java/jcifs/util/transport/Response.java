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
package jcifs.util.transport;


/**
 *
 */
public interface Response extends Message {

    /**
     * 
     * @return whether the response is received
     */
    boolean isReceived ();


    /**
     * Set received status
     */
    void received ();


    /**
     * Unset received status
     */
    void clearReceived ();


    /**
     * 
     * @return number of credits granted by the server
     */
    int getGrantedCredits ();


    /**
     * @return status code
     */
    int getErrorCode ();


    /**
     * @param k
     */
    void setMid ( long k );


    /**
     * @return mid
     */
    long getMid ();


    /**
     * 
     * @param buffer
     * @param i
     * @param size
     * @return whether signature verification is successful
     */
    boolean verifySignature ( byte[] buffer, int i, int size );


    /**
     * @return whether signature verification failed
     */
    boolean isVerifyFailed ();


    /**
     * 
     * @return whether the response is an error
     */
    boolean isError ();


    /**
     * Set error status
     */
    void error ();


    /**
     * 
     * @return the message timeout
     */
    Long getExpiration ();


    /**
     * 
     * @param exp
     *            message timeout
     */
    void setExpiration ( Long exp );


    /**
     * 
     */
    public void reset ();


    /**
     * 
     * @return an exception linked to an error
     */
    public Exception getException ();


    /**
     * @param e
     */
    public void exception ( Exception e );


    /**
     * @return chained response
     */
    Response getNextResponse ();

}
