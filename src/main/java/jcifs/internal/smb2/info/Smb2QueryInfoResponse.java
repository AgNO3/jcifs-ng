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
package jcifs.internal.smb2.info;


import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.Decodable;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.dtyp.SecurityDescriptor;
import jcifs.internal.fscc.FileFsFullSizeInformation;
import jcifs.internal.fscc.FileFsSizeInformation;
import jcifs.internal.fscc.FileInformation;
import jcifs.internal.fscc.FileInternalInfo;
import jcifs.internal.fscc.FileSystemInformation;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public class Smb2QueryInfoResponse extends ServerMessageBlock2Response {

    private byte expectInfoType;
    private byte expectInfoClass;
    private Decodable info;


    /**
     * @param config
     * @param expectInfoType
     * @param expectInfoClass
     */
    public Smb2QueryInfoResponse ( Configuration config, byte expectInfoType, byte expectInfoClass ) {
        super(config);
        this.expectInfoType = expectInfoType;
        this.expectInfoClass = expectInfoClass;
    }


    /**
     * @return the information
     */
    public Decodable getInfo () {
        return this.info;
    }


    /**
     * @param clazz
     * @return the information
     * @throws CIFSException
     */
    @SuppressWarnings ( "unchecked" )
    public <T extends Decodable> T getInfo ( Class<T> clazz ) throws CIFSException {
        if ( !clazz.isAssignableFrom(this.info.getClass()) ) {
            throw new CIFSException("Incompatible file information class");
        }
        return (T) getInfo();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if ( structureSize != 9 ) {
            throw new SMBProtocolDecodingException("Expected structureSize = 9");
        }

        int bufferOffset = SMBUtil.readInt2(buffer, bufferIndex + 2) + getHeaderStart();
        bufferIndex += 4;
        int bufferLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        Decodable i = createInformation(this.expectInfoType, this.expectInfoClass);
        if ( i != null ) {
            i.decode(buffer, bufferOffset, bufferLength);
        }
        bufferIndex = Math.max(bufferIndex, bufferOffset + bufferLength);
        this.info = i;
        return bufferIndex - start;
    }


    private static Decodable createInformation ( byte infoType, byte infoClass ) throws SMBProtocolDecodingException {

        switch ( infoType ) {
        case Smb2Constants.SMB2_0_INFO_FILE:
            return createFileInformation(infoClass);
        case Smb2Constants.SMB2_0_INFO_FILESYSTEM:
            return createFilesystemInformation(infoClass);
        case Smb2Constants.SMB2_0_INFO_QUOTA:
            return createQuotaInformation(infoClass);
        case Smb2Constants.SMB2_0_INFO_SECURITY:
            return createSecurityInformation(infoClass);
        default:
            throw new SMBProtocolDecodingException("Unknwon information type " + infoType);
        }
    }


    /**
     * @param infoClass
     * @return
     * @throws SMBProtocolDecodingException
     */
    private static Decodable createFilesystemInformation ( byte infoClass ) throws SMBProtocolDecodingException {
        switch ( infoClass ) {
        case FileSystemInformation.FS_FULL_SIZE_INFO:
            return new FileFsFullSizeInformation();
        case FileSystemInformation.FS_SIZE_INFO:
            return new FileFsSizeInformation();
        default:
            throw new SMBProtocolDecodingException("Unknown filesystem info class " + infoClass);
        }
    }


    /**
     * @param infoClass
     * @return
     * @throws SMBProtocolDecodingException
     */
    private static Decodable createSecurityInformation ( byte infoClass ) throws SMBProtocolDecodingException {
        return new SecurityDescriptor();
    }


    /**
     * @param infoClass
     * @return
     * @throws SMBProtocolDecodingException
     */
    private static Decodable createQuotaInformation ( byte infoClass ) throws SMBProtocolDecodingException {
        switch ( infoClass ) {
        default:
            throw new SMBProtocolDecodingException("Unknown quota info class " + infoClass);
        }
    }


    /**
     * @param infoClass
     * @return
     * @throws SMBProtocolDecodingException
     */
    private static Decodable createFileInformation ( byte infoClass ) throws SMBProtocolDecodingException {
        switch ( infoClass ) {
        case FileInformation.FILE_INTERNAL_INFO:
            return new FileInternalInfo();
        default:
            throw new SMBProtocolDecodingException("Unknown file info class " + infoClass);
        }
    }

}
