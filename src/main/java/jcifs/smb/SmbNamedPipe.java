/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Paul Walker" <jcifs at samba dot org>
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


import java.net.MalformedURLException;

import jcifs.CIFSContext;


/**
 * This class will allow a Java program to read and write data to Named
 * Pipes and Transact NamedPipes.
 *
 * <p>
 * There are three Win32 function calls provided by the Windows SDK
 * that are important in the context of using jCIFS. They are:
 *
 * <ul>
 * <li><code>CallNamedPipe</code> A message-type pipe call that opens,
 * writes to, reads from, and closes the pipe in a single operation.
 * <li><code>TransactNamedPipe</code> A message-type pipe call that
 * writes to and reads from an existing pipe descriptor in one operation.
 * <li><code>CreateFile</code>, <code>ReadFile</code>,
 * <code>WriteFile</code>, and <code>CloseFile</code> A byte-type pipe can
 * be opened, written to, read from and closed using the standard Win32
 * file operations.
 * </ul>
 *
 * <p>
 * The jCIFS API maps all of these operations into the standard Java
 * <code>XxxputStream</code> interface. A special <code>PIPE_TYPE</code>
 * flags is necessary to distinguish which type of Named Pipe behavior
 * is desired.
 *
 * <p>
 * <table border="1" cellpadding="3" cellspacing="0" width="100%" summary="Usage examples">
 * <tr bgcolor="#ccccff">
 * <td colspan="2"><b><code>SmbNamedPipe</code> Constructor Examples</b></td>
 * <tr>
 * <td width="20%"><b>Code Sample</b></td>
 * <td><b>Description</b></td>
 * </tr>
 * <tr>
 * <td width="20%">
 * 
 * <pre>
 * new SmbNamedPipe("smb://server/IPC$/PIPE/foo", SmbNamedPipe.PIPE_TYPE_RDWR | SmbNamedPipe.PIPE_TYPE_CALL, context);
 * </pre>
 * 
 * </td>
 * <td>
 * Open the Named Pipe foo for reading and writing. The pipe will behave like the <code>CallNamedPipe</code> interface.
 * </td>
 * </tr>
 * <tr>
 * <td width="20%">
 * 
 * <pre>
 * new SmbNamedPipe("smb://server/IPC$/foo", SmbNamedPipe.PIPE_TYPE_RDWR | SmbNamedPipe.PIPE_TYPE_TRANSACT, context);
 * </pre>
 * 
 * </td>
 * <td>
 * Open the Named Pipe foo for reading and writing. The pipe will behave like the <code>TransactNamedPipe</code>
 * interface.
 * </td>
 * </tr>
 * <tr>
 * <td width="20%">
 * 
 * <pre>
 * new SmbNamedPipe("smb://server/IPC$/foo", SmbNamedPipe.PIPE_TYPE_RDWR, context);
 * </pre>
 * 
 * </td>
 * <td>
 * Open the Named Pipe foo for reading and writing. The pipe will
 * behave as though the <code>CreateFile</code>, <code>ReadFile</code>,
 * <code>WriteFile</code>, and <code>CloseFile</code> interface was
 * being used.
 * </td>
 * </tr>
 * </table>
 *
 * <p>
 * See <a href="../../../pipes.html">Using jCIFS to Connect to Win32
 * Named Pipes</a> for a detailed description of how to use jCIFS with
 * Win32 Named Pipe server processes.
 *
 */

public class SmbNamedPipe extends SmbFile {

    /**
     * The pipe should be opened read-only.
     */

    public static final int PIPE_TYPE_RDONLY = O_RDONLY;

    /**
     * The pipe should be opened only for writing.
     */

    public static final int PIPE_TYPE_WRONLY = O_WRONLY;

    /**
     * The pipe should be opened for both reading and writing.
     */

    public static final int PIPE_TYPE_RDWR = O_RDWR;

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

    private final int pipeType;


    /**
     * Open the Named Pipe resource specified by the url
     * parameter. The pipeType parameter should be at least one of
     * the <code>PIPE_TYPE</code> flags combined with the bitwise OR
     * operator <code>|</code>. See the examples listed above.
     * 
     * @param url
     * @param pipeType
     * @param unshared
     *            whether to use an exclusive connection for this pipe
     * @param tc
     * @throws MalformedURLException
     */

    public SmbNamedPipe ( String url, int pipeType, boolean unshared, CIFSContext tc ) throws MalformedURLException {
        super(url, tc);
        this.pipeType = pipeType;
        setNonPooled(unshared);
        if ( !getFileLocator().isIPC() ) {
            throw new MalformedURLException("Named pipes are only valid on IPC$");
        }
        this.fileLocator.updateType(TYPE_NAMED_PIPE);
    }


    /**
     * Open the Named Pipe resource specified by the url
     * parameter. The pipeType parameter should be at least one of
     * the <code>PIPE_TYPE</code> flags combined with the bitwise OR
     * operator <code>|</code>. See the examples listed above.
     * 
     * @param url
     * @param pipeType
     * @param tc
     * @throws MalformedURLException
     */
    public SmbNamedPipe ( String url, int pipeType, CIFSContext tc ) throws MalformedURLException {
        this(url, pipeType, false, tc);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFile#customizeCreate(jcifs.smb.SmbComNTCreateAndX, jcifs.smb.SmbComNTCreateAndXResponse)
     */
    @Override
    protected void customizeCreate ( SmbComNTCreateAndX request, SmbComNTCreateAndXResponse response ) {
        request.flags0 |= 0x16;
        response.isExtended = true;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFile#getType()
     */
    @Override
    public int getType () throws SmbException {
        return TYPE_NAMED_PIPE;
    }


    /**
     * @return the pipe type
     */
    public int getPipeType () {
        return this.pipeType;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFile#getUncPath()
     */
    @Override
    public String getUncPath () {
        return super.getUncPath();
    }


    /**
     * @return a handle for interacting with the pipe
     */
    public SmbPipeHandleImpl openPipe () {
        return new SmbPipeHandleImpl(this);
    }

}
