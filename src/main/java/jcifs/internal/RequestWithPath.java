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
public interface RequestWithPath extends CommonServerMessageBlock {

    /**
     * @return the path to the resource (below share)
     */
    String getPath ();


    /**
     * 
     * @return the server name
     */
    String getServer ();


    /**
     * 
     * @return the domain name
     */
    String getDomain ();


    /**
     * 
     * @return the full UNC path
     */
    String getFullUNCPath ();


    /**
     * @param path
     */
    void setPath ( String path );


    /**
     * 
     * @param domain
     * @param server
     * @param fullPath
     */
    void setFullUNCPath ( String domain, String server, String fullPath );


    /**
     * @param resolve
     * 
     */
    void setResolveInDfs ( boolean resolve );


    /**
     * 
     * @return whether to resolve the request path in DFS
     */
    boolean isResolveInDfs ();

}
