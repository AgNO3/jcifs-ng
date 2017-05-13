/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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


import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SmbPipeHandle;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;


class TransCallNamedPipeResponse extends SmbComTransactionResponse {

    private static final Logger log = LoggerFactory.getLogger(TransCallNamedPipeResponse.class);
    private SmbPipeHandle pipe;


    TransCallNamedPipeResponse ( Configuration config, SmbPipeHandle pipe ) {
        super(config);
        this.pipe = pipe;
    }


    @Override
    protected int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int writeDataWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int readSetupWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    protected int readParametersWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @SuppressWarnings ( "resource" )
    @Override
    protected int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        InputStream input;
        try {
            input = this.pipe.getInput();
        }
        catch ( CIFSException e ) {
            log.error("Failed to get pipe input stream", e);
            input = null;
        }
        if ( input instanceof TransactNamedPipeInputStream ) {
            TransactNamedPipeInputStream in = (TransactNamedPipeInputStream) input;
            synchronized ( in.lock ) {
                in.receive(buffer, bufferIndex, len);
                in.lock.notify();
            }
        }
        return len;
    }


    @Override
    public String toString () {
        return new String("TransCallNamedPipeResponse[" + super.toString() + "]");
    }
}
