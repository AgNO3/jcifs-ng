/* jcifs msrpc client library in Java
 * Copyright (C) 2007  "Michael B. Allen" <jcifs at samba dot org>
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


import java.io.IOException;

import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.rpc;
import jcifs.smb.SmbException;


@SuppressWarnings ( "javadoc" )
public class SamrDomainHandle extends rpc.policy_handle implements AutoCloseable {

    private final DcerpcHandle handle;
    private boolean opened;


    public SamrDomainHandle ( DcerpcHandle handle, SamrPolicyHandle policyHandle, int access, rpc.sid_t sid ) throws IOException {
        this.handle = handle;
        MsrpcSamrOpenDomain rpc = new MsrpcSamrOpenDomain(policyHandle, access, sid, this);
        handle.sendrecv(rpc);
        if ( rpc.retval != 0 ) {
            throw new SmbException(rpc.retval, false);
        }
        this.opened = true;
    }


    @Override
    public synchronized void close () throws IOException {
        if ( this.opened ) {
            this.opened = false;
            MsrpcSamrCloseHandle rpc = new MsrpcSamrCloseHandle(this);
            this.handle.sendrecv(rpc);
            if ( rpc.retval != 0 ) {
                throw new SmbException(rpc.retval, false);
            }
        }
    }
}
