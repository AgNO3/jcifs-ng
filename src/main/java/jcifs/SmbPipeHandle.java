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
package jcifs;


import java.io.InputStream;
import java.io.OutputStream;


/**
 * Handle to an open named pipe
 * 
 * @author mbechler
 *
 */
public interface SmbPipeHandle extends AutoCloseable {

    /**
     * @return the pipe
     */
    SmbPipeResource getPipe ();


    /**
     * 
     * @return this pipe's input stream
     * @throws CIFSException
     */
    InputStream getInput () throws CIFSException;


    /**
     * 
     * @return this pipe's output stream
     * @throws CIFSException
     */
    OutputStream getOutput () throws CIFSException;


    /**
     * {@inheritDoc}
     * 
     * @throws CIFSException
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    void close () throws CIFSException;


    /**
     * @return whether the FD is open and valid
     */
    boolean isOpen ();


    /**
     * @return whether the FD was previously open but became invalid
     */
    boolean isStale ();


    /**
     * @param type
     * @return unwrapped instance
     */
    <T extends SmbPipeHandle> T unwrap ( Class<T> type );

}