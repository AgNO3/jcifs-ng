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
 *
 */
public interface Request extends Message {

    /**
     * @return number of credits this request requires
     */
    int getCreditCost ();


    /**
     * @param credits
     */
    void setRequestCredits ( int credits );


    /**
     * @return whether this is a cancel request
     */
    boolean isCancel ();


    /**
     * @return chained request
     */
    Request getNext ();


    /**
     * @return the response for this request
     */
    Response getResponse ();

}
