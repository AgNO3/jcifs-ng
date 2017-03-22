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
import java.net.MalformedURLException;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.SmbConstants;


/**
 * @author mbechler
 *
 */
final class SmbCopyUtil {

    private static final Logger log = LoggerFactory.getLogger(SmbCopyUtil.class);


    /**
     * 
     */
    private SmbCopyUtil () {}


    /**
     * @param dest
     * @return
     * @throws SmbException
     * @throws SmbAuthException
     */
    static SmbFileHandleImpl openCopyTargetFile ( SmbFile dest, int attrs ) throws SmbException, SmbAuthException {
        try {
            return dest.openUnshared(
                SmbFile.O_CREAT | SmbFile.O_WRONLY | SmbFile.O_TRUNC,
                SmbConstants.FILE_WRITE_DATA | SmbConstants.FILE_WRITE_ATTRIBUTES,
                attrs,
                0);
        }
        catch ( SmbAuthException sae ) {
            log.trace("copyTo0", sae);
            int dattrs = dest.getAttributes();
            if ( ( dattrs & SmbFile.ATTR_READONLY ) != 0 ) {
                /*
                 * Remove READONLY and try again
                 */
                dest.setPathInformation(dattrs & ~SmbFile.ATTR_READONLY, 0L, 0L, 0L);
                return dest.openUnshared(
                    SmbFile.O_CREAT | SmbFile.O_WRONLY | SmbFile.O_TRUNC,
                    SmbConstants.FILE_WRITE_DATA | SmbConstants.FILE_WRITE_ATTRIBUTES,
                    attrs,
                    0);
            }
            throw sae;
        }
    }


    /**
     * @param dest
     * @param b
     * @param bsize
     * @param w
     * @param dh
     * @param sh
     * @param req
     * @param resp
     * @throws SmbException
     */
    static void copyFile ( SmbFile src, SmbFile dest, byte[][] b, int bsize, WriterThread w, SmbTreeHandleImpl sh, SmbTreeHandleImpl dh )
            throws SmbException {
        try ( SmbFileHandleImpl sfd = src.openUnshared(SmbFile.O_RDONLY, 0, SmbFile.ATTR_NORMAL, 0);
              SmbFileInputStream fis = new SmbFileInputStream(src, sh, sfd) ) {
            int attrs = src.getAttributes();
            try ( SmbFileHandleImpl dfd = openCopyTargetFile(dest, attrs);
                  SmbFileOutputStream fos = new SmbFileOutputStream(dest, dh, dfd) ) {
                long mtime = src.lastModified();
                long ctime = src.createTime();
                long atime = src.lastAccess();
                int i = 0;
                long off = 0L;
                while ( true ) {
                    int read = fis.read(b[ i ]);
                    synchronized ( w ) {
                        w.checkException();
                        while ( !w.isReady() ) {
                            try {
                                w.wait();
                            }
                            catch ( InterruptedException ie ) {
                                throw new SmbException(dest.getURL().toString(), ie);
                            }
                        }
                        w.checkException();

                        if ( read <= 0 ) {
                            break;
                        }

                        w.write(b[ i ], read, fos);
                    }

                    i = i == 1 ? 0 : 1;
                    off += read;
                }

                if ( log.isDebugEnabled() ) {
                    log.debug(String.format("Copied a total of %d bytes", off));
                }

                if ( dh.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                    // use the open file descriptor
                    dh.send(
                        new Trans2SetFileInformation(dh.getConfig(), dfd.getFid(), attrs, ctime, mtime, atime),
                        new Trans2SetFileInformationResponse(dh.getConfig()));
                }
                else {
                    dh.send(
                        new SmbComSetInformation(dh.getConfig(), dest.getUncPath(), attrs, mtime),
                        new SmbComSetInformationResponse(dh.getConfig()));
                }
            }
        }
        catch ( IOException se ) {
            if ( !src.getTransportContext().getConfig().isIgnoreCopyToException() ) {
                throw new SmbException("Failed to copy file from [" + src.toString() + "] to [" + dest.toString() + "]", se);
            }
            log.debug("Copy failed", se);
        }
    }


    /**
     * @param dest
     * @param b
     * @param bsize
     * @param w
     * @param dh
     * @param sh
     * @param req
     * @param resp
     * @throws SmbException
     */
    static void copyDir ( SmbFile src, SmbFile dest, byte[][] b, int bsize, WriterThread w, SmbTreeHandleImpl sh, SmbTreeHandleImpl dh )
            throws SmbException {
        int i;
        String path = dest.getFileLocator().getUNCPath();
        if ( path.length() > 1 ) {
            try {
                dest.mkdir();
                if ( dh.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                    dest.setPathInformation(src.getAttributes(), src.createTime(), src.lastModified(), src.lastAccess());
                }
                else {
                    dest.setPathInformation(src.getAttributes(), 0L, src.lastModified(), 0L);
                }
            }
            catch ( SmbException se ) {
                log.trace("copyTo0", se);
                if ( se.getNtStatus() != NtStatus.NT_STATUS_ACCESS_DENIED && se.getNtStatus() != NtStatus.NT_STATUS_OBJECT_NAME_COLLISION ) {
                    throw se;
                }
            }
        }

        SmbFile[] files = src.listFiles("*", SmbFile.ATTR_DIRECTORY | SmbFile.ATTR_HIDDEN | SmbFile.ATTR_SYSTEM, null, null);
        try {
            for ( i = 0; i < files.length; i++ ) {
                try ( SmbFile ndest = new SmbFile(
                    dest,
                    files[ i ].getFileLocator().getName(),
                    true,
                    files[ i ].getFileLocator().getType(),
                    files[ i ].getAttributes(),
                    files[ i ].createTime(),
                    files[ i ].lastModified(),
                    files[ i ].lastAccess(),
                    files[ i ].length()) ) {
                    try {
                        files[ i ].copyRecursive(ndest, b, bsize, w, sh, dh);
                    }
                    finally {
                        files[ i ].close();
                    }
                }
            }
        }
        catch ( UnknownHostException uhe ) {
            throw new SmbException(src.getURL().toString(), uhe);
        }
        catch ( MalformedURLException mue ) {
            throw new SmbException(src.getURL().toString(), mue);
        }
    }

}


class WriterThread extends Thread {

    private byte[] b;
    private int n;
    private boolean ready;
    private SmbFileOutputStream out;

    private SmbException e = null;


    WriterThread () {
        super("JCIFS-WriterThread");
        this.ready = false;
    }


    /**
     * @return the ready
     */
    boolean isReady () {
        return this.ready;
    }


    /**
     * @throws SmbException
     * 
     */
    public void checkException () throws SmbException {
        if ( this.e != null ) {
            throw this.e;
        }
    }


    synchronized void write ( byte[] buffer, int len, SmbFileOutputStream d ) {
        this.b = buffer;
        this.n = len;
        this.out = d;
        this.ready = false;
        notify();
    }


    @Override
    public void run () {
        synchronized ( this ) {
            try {
                for ( ;; ) {
                    notify();
                    this.ready = true;
                    while ( this.ready ) {
                        wait();
                    }
                    if ( this.n == -1 ) {
                        return;
                    }

                    this.out.write(this.b, 0, this.n);
                }
            }
            catch ( SmbException ex ) {
                this.e = ex;
            }
            catch ( Exception x ) {
                this.e = new SmbException("WriterThread", x);
            }
            notify();
        }
    }

}
