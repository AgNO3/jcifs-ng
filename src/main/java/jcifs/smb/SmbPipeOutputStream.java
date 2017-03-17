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


/**
 * @author mbechler
 *
 */
public class SmbPipeOutputStream extends SmbFileOutputStream {

    private SmbPipeHandle handle;


    /**
     * @param handle
     * @throws SmbException
     */
    SmbPipeOutputStream ( SmbPipeHandle handle, SmbTreeHandleImpl th ) throws SmbException {
        super(handle.getPipe(), th);
        this.handle = handle;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileOutputStream#isOpen()
     */
    @Override
    public boolean isOpen () {
        return this.handle.isOpen();
    }


    @Override
    protected synchronized SmbTreeHandleImpl ensureTreeConnected () throws SmbException {
        return this.handle.ensureTreeConnected();
    }


    @Override
    protected synchronized SmbFileHandleImpl ensureOpen () throws SmbException {
        return this.handle.ensureOpen();
    }


    @Override
    public void close () {
        // ignore, the shared file descriptor is closed by the pipe handle
    }
}
