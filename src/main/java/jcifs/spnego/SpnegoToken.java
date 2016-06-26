/* jcifs smb client library in Java
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package jcifs.spnego;


import java.io.IOException;


@SuppressWarnings ( "javadoc" )
public abstract class SpnegoToken {

    private byte[] mechanismToken;

    private byte[] mechanismListMIC;


    public byte[] getMechanismToken () {
        return this.mechanismToken;
    }


    public void setMechanismToken ( byte[] mechanismToken ) {
        this.mechanismToken = mechanismToken;
    }


    public byte[] getMechanismListMIC () {
        return this.mechanismListMIC;
    }


    public void setMechanismListMIC ( byte[] mechanismListMIC ) {
        this.mechanismListMIC = mechanismListMIC;
    }


    public abstract byte[] toByteArray ();


    protected abstract void parse ( byte[] token ) throws IOException;

}
