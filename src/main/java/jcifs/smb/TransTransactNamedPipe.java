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


import org.apache.log4j.Logger;

import jcifs.Configuration;


class TransTransactNamedPipe extends SmbComTransaction {

    private static final Logger log = Logger.getLogger(TransTransactNamedPipe.class);

    private byte[] pipeData;
    private int pipeFid, pipeDataOff, pipeDataLen;


    TransTransactNamedPipe ( Configuration config, int fid, byte[] data, int off, int len ) {
        super(config);
        this.pipeFid = fid;
        this.pipeData = data;
        this.pipeDataOff = off;
        this.pipeDataLen = len;
        this.command = SMB_COM_TRANSACTION;
        this.subCommand = TRANS_TRANSACT_NAMED_PIPE;
        this.maxParameterCount = 0;
        this.maxDataCount = 0xFFFF;
        this.maxSetupCount = (byte) 0x00;
        this.setupCount = 2;
        this.name = "\\PIPE\\";
    }


    @Override
    int writeSetupWireFormat ( byte[] dst, int dstIndex ) {
        dst[ dstIndex++ ] = this.subCommand;
        dst[ dstIndex++ ] = (byte) 0x00;
        SMBUtil.writeInt2(this.pipeFid, dst, dstIndex);
        dstIndex += 2;
        return 4;
    }


    @Override
    int readSetupWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    int writeParametersWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    int writeDataWireFormat ( byte[] dst, int dstIndex ) {
        if ( ( dst.length - dstIndex ) < this.pipeDataLen ) {
            log.debug("TransTransactNamedPipe data too long for buffer");
            return 0;
        }
        System.arraycopy(this.pipeData, this.pipeDataOff, dst, dstIndex, this.pipeDataLen);
        return this.pipeDataLen;
    }


    @Override
    int readParametersWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    int readDataWireFormat ( byte[] buffer, int bufferIndex, int len ) {
        return 0;
    }


    @Override
    public String toString () {
        return new String("TransTransactNamedPipe[" + super.toString() + ",pipeFid=" + this.pipeFid + "]");
    }
}
