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


import java.io.DataInput;
import java.io.DataOutput;

import jcifs.smb.SmbException;


/**
 * File access that exposes random access semantics
 * 
 * @author mbechler
 *
 */
public interface SmbRandomAccess extends DataOutput, DataInput, AutoCloseable {

    /**
     * Close the file
     * 
     * @throws SmbException
     */
    @Override
    void close () throws SmbException;


    /**
     * Read a single byte from the current position
     * 
     * @return read byte, -1 if EOF
     * @throws SmbException
     */
    int read () throws SmbException;


    /**
     * Read into buffer from current position
     * 
     * @param b
     *            buffer
     * @return number of bytes read
     * @throws SmbException
     */
    int read ( byte[] b ) throws SmbException;


    /**
     * Read into buffer from current position
     * 
     * @param b
     *            buffer
     * @param off
     *            offset into buffer
     * @param len
     *            read up to <tt>len</tt> bytes
     * @return number of bytes read
     * @throws SmbException
     */
    int read ( byte[] b, int off, int len ) throws SmbException;


    /**
     * Current position in file
     * 
     * @return current position
     */
    long getFilePointer ();


    /**
     * Seek to new position
     * 
     * @param pos
     */
    void seek ( long pos );


    /**
     * Get the current file length
     * 
     * @return file length
     * @throws SmbException
     */
    long length () throws SmbException;


    /**
     * Expand/truncate file length
     * 
     * @param newLength
     *            new file length
     * @throws SmbException
     */
    void setLength ( long newLength ) throws SmbException;

}
