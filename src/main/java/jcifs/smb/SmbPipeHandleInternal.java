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
package jcifs.smb;


import java.io.IOException;

import jcifs.CIFSException;
import jcifs.SmbFileHandle;
import jcifs.SmbPipeHandle;


/**
 * @author mbechler
 * @internal
 */
public interface SmbPipeHandleInternal extends SmbPipeHandle {

    /**
     * @return the pipe type
     */
    int getPipeType ();


    /**
     * @return session key of the underlying smb session
     * @throws CIFSException
     */
    byte[] getSessionKey () throws CIFSException;


    /**
     * 
     * @return this pipe's input stream
     * @throws SmbException
     */
    @Override
    SmbPipeInputStream getInput () throws CIFSException;


    /**
     * 
     * @return this pipe's output stream
     * @throws SmbException
     * @throws
     */
    @Override
    SmbPipeOutputStream getOutput () throws CIFSException;


    /**
     * @return tree connection
     * @throws SmbException
     * @throws CIFSException
     */
    SmbTreeHandleInternal ensureTreeConnected () throws CIFSException;


    /**
     * @return file handle
     * @throws CIFSException
     */
    SmbFileHandle ensureOpen () throws CIFSException;


    /**
     * @param buf
     * @param off
     * @param length
     * @param direct
     * @return received bytes
     * @throws CIFSException
     * @throws IOException
     */
    int recv ( byte[] buf, int off, int length ) throws IOException;


    /**
     * @param buf
     * @param off
     * @param length
     * @param direct
     * @throws IOException
     */
    void send ( byte[] buf, int off, int length ) throws IOException;


    /**
     * @param buf
     * @param off
     * @param length
     * @param inB
     * @param maxRecvCnt
     * @return len
     * @throws IOException
     */
    int sendrecv ( byte[] buf, int off, int length, byte[] inB, int maxRecvCnt ) throws IOException;
}
