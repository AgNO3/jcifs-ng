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

package jcifs.internal.smb1.com;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Configuration;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;
import jcifs.internal.util.SigningDigest;


/**
 * 
 *
 */
public class SmbComClose extends ServerMessageBlock {

    private static final Logger log = LoggerFactory.getLogger(SmbComClose.class);

    private int fid;
    private long lastWriteTime;


    /**
     * 
     * @param config
     * @param fid
     * @param lastWriteTime
     */
    public SmbComClose ( Configuration config, int fid, long lastWriteTime ) {
        super(config, SMB_COM_CLOSE);
        this.fid = fid;
        this.lastWriteTime = lastWriteTime;
    }


    @Override
    protected int writeParameterWordsWireFormat ( byte[] dst, int dstIndex ) {
        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        if ( this.digest != null ) {
            SigningDigest.writeUTime(getConfig(), this.lastWriteTime, dst, dstIndex);
        }
        else {
            log.trace("SmbComClose without a digest");
        }
        return 6;
    }


    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    @Override
    protected int readParameterWordsWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) {
        return 0;
    }


    @Override
    public String toString () {
        return new String("SmbComClose[" + super.toString() + ",fid=" + this.fid + ",lastWriteTime=" + this.lastWriteTime + "]");
    }
}
