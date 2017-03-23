/*
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
package jcifs.dcerpc.msrpc;


import jcifs.dcerpc.rpc.sid_t;
import jcifs.smb.SID;


class LsarSidArrayX extends lsarpc.LsarSidArray {

    LsarSidArrayX ( jcifs.SID[] sids ) {
        this.num_sids = sids.length;
        this.sids = new lsarpc.LsarSidPtr[sids.length];
        for ( int si = 0; si < sids.length; si++ ) {
            this.sids[ si ] = new lsarpc.LsarSidPtr();
            this.sids[ si ].sid = sids[ si ].unwrap(sid_t.class);
        }
    }


    LsarSidArrayX ( SID[] sids ) {
        this.num_sids = sids.length;
        this.sids = new lsarpc.LsarSidPtr[sids.length];
        for ( int si = 0; si < sids.length; si++ ) {
            this.sids[ si ] = new lsarpc.LsarSidPtr();
            this.sids[ si ].sid = sids[ si ];
        }
    }
}
