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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.CloseableIterator;
import jcifs.SmbConstants;
import jcifs.SmbResource;
import jcifs.internal.fscc.FileBasicInfo;
import jcifs.internal.smb1.com.SmbComSetInformation;
import jcifs.internal.smb1.com.SmbComSetInformationResponse;
import jcifs.internal.smb1.trans2.Trans2SetFileInformation;
import jcifs.internal.smb1.trans2.Trans2SetFileInformationResponse;
import jcifs.internal.smb2.info.Smb2SetInfoRequest;
import jcifs.internal.smb2.ioctl.Smb2IoctlRequest;
import jcifs.internal.smb2.ioctl.Smb2IoctlResponse;
import jcifs.internal.smb2.ioctl.SrvCopyChunkCopyResponse;
import jcifs.internal.smb2.ioctl.SrvCopychunk;
import jcifs.internal.smb2.ioctl.SrvCopychunkCopy;
import jcifs.internal.smb2.ioctl.SrvRequestResumeKeyResponse;


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
    static SmbFileHandleImpl openCopyTargetFile ( SmbFile dest, int attrs, boolean alsoRead ) throws CIFSException {
        try {
            return dest.openUnshared(
                SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
                SmbConstants.FILE_WRITE_DATA | SmbConstants.FILE_WRITE_ATTRIBUTES | ( alsoRead ? SmbConstants.FILE_READ_DATA : 0 ),
                SmbConstants.FILE_NO_SHARE,
                attrs,
                0);
        }
        catch ( SmbAuthException sae ) {
            log.trace("copyTo0", sae);
            int dattrs = dest.getAttributes();
            if ( ( dattrs & SmbConstants.ATTR_READONLY ) != 0 ) {
                /*
                 * Remove READONLY and try again
                 */
                dest.setPathInformation(dattrs & ~SmbConstants.ATTR_READONLY, 0L, 0L, 0L);
                return dest.openUnshared(
                    SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
                    SmbConstants.FILE_WRITE_DATA | SmbConstants.FILE_WRITE_ATTRIBUTES | ( alsoRead ? SmbConstants.FILE_READ_DATA : 0 ),
                    SmbConstants.FILE_NO_SHARE,
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

        if ( sh.isSMB2() && dh.isSMB2() && sh.isSameTree(dh) ) {
            try {
                serverSideCopy(src, dest, sh, dh, false);
                return;
            }
            catch ( CIFSException e ) {
                log.warn("Server side copy failed", e);
                throw SmbException.wrap(e);
            }
        }

        try ( SmbFileHandleImpl sfd = src.openUnshared(0, SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, SmbConstants.ATTR_NORMAL, 0);
              SmbFileInputStream fis = new SmbFileInputStream(src, sh, sfd) ) {
            int attrs = src.getAttributes();

            try ( SmbFileHandleImpl dfd = openCopyTargetFile(dest, attrs, false);
                  SmbFileOutputStream fos = new SmbFileOutputStream(
                      dest,
                      dh,
                      dfd,
                      SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
                      SmbConstants.FILE_WRITE_DATA | SmbConstants.FILE_WRITE_ATTRIBUTES,
                      SmbConstants.FILE_NO_SHARE) ) {
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

                if ( dh.isSMB2() ) {
                    Smb2SetInfoRequest req = new Smb2SetInfoRequest(dh.getConfig(), dfd.getFileId());
                    req.setFileInformation(new FileBasicInfo(ctime, atime, mtime, 0L, attrs));
                    dh.send(req);
                }
                else if ( dh.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
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
            if ( !src.getContext().getConfig().isIgnoreCopyToException() ) {
                throw new SmbException("Failed to copy file from [" + src.toString() + "] to [" + dest.toString() + "]", se);
            }
            log.warn("Copy failed", se);
        }
    }


    /**
     * @param src
     * @param dest
     * @param sh
     * @param dh
     * @throws SmbException
     */
    @SuppressWarnings ( "resource" )
    private static void serverSideCopy ( SmbFile src, SmbFile dest, SmbTreeHandleImpl sh, SmbTreeHandleImpl dh, boolean write ) throws CIFSException {
        log.debug("Trying server side copy");
        SmbFileHandleImpl dfd = null;
        try {
            long size;
            byte[] resumeKey;

            // despite there being a resume key, we still need an open file descriptor?
            try ( SmbFileHandleImpl sfd = src.openUnshared(0, SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, SmbConstants.ATTR_NORMAL, 0) ) {
                if ( sfd.getInitialSize() == 0 ) {
                    try ( SmbFileHandleImpl edfd = openCopyTargetFile(dest, src.getAttributes(), !write) ) {
                        return;
                    }
                }

                Smb2IoctlRequest resumeReq = new Smb2IoctlRequest(sh.getConfig(), Smb2IoctlRequest.FSCTL_SRV_REQUEST_RESUME_KEY, sfd.getFileId());
                resumeReq.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
                Smb2IoctlResponse resumeResp = sh.send(resumeReq);
                SrvRequestResumeKeyResponse rkresp = resumeResp.getOutputData(SrvRequestResumeKeyResponse.class);
                size = sfd.getInitialSize();
                resumeKey = rkresp.getResumeKey();

                // start with some reasonably safe defaults, the server will till us if it does not like it
                // can we resume this if we loose the file descriptor?

                int maxChunks = 256;
                int maxChunkSize = 1024 * 1024;
                int byteLimit = 16 * 1024 * 1024;
                boolean retry = false;
                do {
                    long ooff = 0;
                    while ( ooff < size ) {
                        long wsize = size - ooff;
                        if ( wsize > byteLimit ) {
                            wsize = byteLimit;
                        }

                        int chunks = (int) ( wsize / maxChunkSize );
                        int lastChunkSize;
                        if ( chunks + 1 > maxChunks ) {
                            chunks = maxChunks;
                            lastChunkSize = maxChunkSize;
                        }
                        else {
                            lastChunkSize = (int) ( wsize % maxChunkSize );
                            if ( lastChunkSize != 0 ) {
                                chunks++;
                            }
                            else {
                                lastChunkSize = maxChunkSize;
                            }
                        }

                        SrvCopychunk[] chunkInfo = new SrvCopychunk[chunks];
                        long ioff = 0;
                        for ( int i = 0; i < chunks; i++ ) {
                            long absoff = ooff + ioff;
                            int csize = i == chunks - 1 ? lastChunkSize : maxChunkSize;
                            chunkInfo[ i ] = new SrvCopychunk(absoff, absoff, csize);
                            ioff += maxChunkSize;
                        }

                        if ( dfd == null || !dfd.isValid() ) {
                            // don't reopen the file for every round if it's not necessary, keep the lock
                            dfd = openCopyTargetFile(dest, src.getAttributes(), !write);
                        }

                        // FSCTL_SRV_COPYCHUNK_WRITE allows to open the file for writing only, FSCTL_SRV_COPYCHUNK also
                        // needs read access
                        Smb2IoctlRequest copy = new Smb2IoctlRequest(
                            sh.getConfig(),
                            write ? Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK_WRITE : Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK,
                            dfd.getFileId());
                        copy.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
                        copy.setInputData(new SrvCopychunkCopy(resumeKey, chunkInfo));

                        try {
                            SrvCopyChunkCopyResponse r = dh.send(copy, RequestParam.NO_RETRY).getOutputData(SrvCopyChunkCopyResponse.class);
                            if ( log.isDebugEnabled() ) {
                                log.debug(
                                    String.format(
                                        "Wrote %d bytes (%d chunks, last partial write %d)",
                                        r.getTotalBytesWritten(),
                                        r.getChunksWritten(),
                                        r.getChunkBytesWritten()));
                            }
                            ooff += r.getTotalBytesWritten();
                        }
                        catch ( SmbException e ) {
                            Smb2IoctlResponse response = copy.getResponse();
                            if ( !retry && response.isReceived() && !response.isError()
                                    && response.getStatus() == NtStatus.NT_STATUS_INVALID_PARAMETER ) {
                                retry = true;
                                SrvCopyChunkCopyResponse outputData = response.getOutputData(SrvCopyChunkCopyResponse.class);
                                maxChunks = outputData.getChunksWritten();
                                maxChunkSize = outputData.getChunkBytesWritten();
                                byteLimit = outputData.getTotalBytesWritten();
                                continue;
                            }
                            throw e;
                        }
                    }
                    break;
                }
                while ( retry );
            }
        }
        catch ( IOException se ) {
            throw new CIFSException("Server side copy failed", se);
        }
        finally {
            if ( dfd != null ) {
                dfd.close();
            }
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
            throws CIFSException {
        String path = dest.getLocator().getUNCPath();
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
            catch ( SmbUnsupportedOperationException e ) {
                if ( src.getContext().getConfig().isIgnoreCopyToException() ) {
                    log.warn("Failed to set file attributes on " + path, e);
                }
                else {
                    throw e;
                }
            }
            catch ( SmbException se ) {
                log.trace("copyTo0", se);
                if ( se.getNtStatus() != NtStatus.NT_STATUS_ACCESS_DENIED && se.getNtStatus() != NtStatus.NT_STATUS_OBJECT_NAME_COLLISION ) {
                    throw se;
                }
            }
        }

        try ( CloseableIterator<SmbResource> it = SmbEnumerationUtil
                .doEnum(src, "*", SmbConstants.ATTR_DIRECTORY | SmbConstants.ATTR_HIDDEN | SmbConstants.ATTR_SYSTEM, null, null) ) {
            while ( it.hasNext() ) {
                try ( SmbResource r = it.next() ) {
                    try ( SmbFile ndest = new SmbFile(
                        dest,
                        r.getLocator().getName(),
                        true,
                        r.getLocator().getType(),
                        r.getAttributes(),
                        r.createTime(),
                        r.lastModified(),
                        r.lastAccess(),
                        r.length()) ) {

                        if ( r instanceof SmbFile ) {
                            ( (SmbFile) r ).copyRecursive(ndest, b, bsize, w, sh, dh);
                        }

                    }
                }
            }
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
