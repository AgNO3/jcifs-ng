/* jcifs smb client library in Java
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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


import java.util.Map;


@SuppressWarnings ( "javadoc" )
public class DfsReferral extends SmbException {

    /**
     * 
     */
    private static final long serialVersionUID = 1486630733410281686L;

    public int pathConsumed;
    public long ttl;
    public String server; // Server
    public String share; // Share
    public String link;
    public String path; // Path relative to tree from which this referral was thrown
    public boolean resolveHashes;
    public long expiration;
    public int rflags;

    DfsReferral next;
    Map<String, DfsReferral> map;
    String key = null;


    /**
     * 
     */
    public DfsReferral () {
        this.next = this;
    }


    void append ( DfsReferral dr ) {
        dr.next = this.next;
        this.next = dr;
    }


    @Override
    public String toString () {
        return "DfsReferral[pathConsumed=" + this.pathConsumed + ",server=" + this.server + ",share=" + this.share + ",link=" + this.link + ",path="
                + this.path + ",ttl=" + this.ttl + ",expiration=" + this.expiration + ",remain=" + ( this.expiration - System.currentTimeMillis() )
                + ",resolveHashes=" + this.resolveHashes + "]";
    }
}
