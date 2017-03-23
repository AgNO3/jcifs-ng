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


/**
 * SMB resource respresenting a named pipe
 * 
 * @author mbechler
 *
 */
public interface SmbPipeResource extends SmbResource {

    /**
     * The pipe should be opened read-only.
     */

    public static final int PIPE_TYPE_RDONLY = SmbConstants.O_RDONLY;

    /**
     * The pipe should be opened only for writing.
     */

    public static final int PIPE_TYPE_WRONLY = SmbConstants.O_WRONLY;

    /**
     * The pipe should be opened for both reading and writing.
     */

    public static final int PIPE_TYPE_RDWR = SmbConstants.O_RDWR;

    /**
     * Pipe operations should behave like the <code>CallNamedPipe</code> Win32 Named Pipe function.
     */

    public static final int PIPE_TYPE_CALL = 0x0100;

    /**
     * Pipe operations should behave like the <code>TransactNamedPipe</code> Win32 Named Pipe function.
     */

    public static final int PIPE_TYPE_TRANSACT = 0x0200;

    /**
     * Pipe is used for DCE
     */
    public static final int PIPE_TYPE_DCE_TRANSACT = 0x0200 | 0x0400;

    /**
     * Pipe should use it's own exclusive transport connection
     */
    public static final int PIPE_TYPE_UNSHARED = 0x800;


    /**
     * @return the type of the pipe
     */
    int getPipeType ();


    /**
     * Create a pipe handle
     * 
     * @return pipe handle, needs to be closed when finished
     */
    SmbPipeHandle openPipe ();

}
