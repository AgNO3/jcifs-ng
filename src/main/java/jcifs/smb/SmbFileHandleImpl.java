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


import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.log4j.Logger;

import jcifs.Configuration;


/**
 * @author mbechler
 *
 */
public class SmbFileHandleImpl implements SmbFileHandle {

    private static final Logger log = Logger.getLogger(SmbFileHandleImpl.class);

    private final Configuration cfg;
    private final int fid;
    private boolean open = true;
    private final long tree_num; // for checking whether the tree changed
    private SmbTreeHandleImpl tree;

    private final AtomicLong usageCount = new AtomicLong(1);
    private final int flags;
    private final int access;
    private final int attrs;
    private final int options;
    private final String unc;

    private final StackTraceElement[] creationBacktrace;


    /**
     * @param cfg
     * @param fid
     * @param tree
     * @param unc
     * @param options
     * @param attrs
     * @param access
     * @param flags
     */
    public SmbFileHandleImpl ( Configuration cfg, int fid, SmbTreeHandleImpl tree, String unc, int flags, int access, int attrs, int options ) {
        this.cfg = cfg;
        this.fid = fid;
        this.unc = unc;
        this.flags = flags;
        this.access = access;
        this.attrs = attrs;
        this.options = options;
        this.tree = tree.acquire();
        this.tree_num = tree.getTreeId();

        if ( cfg.isTraceResourceUsage() ) {
            this.creationBacktrace = Thread.currentThread().getStackTrace();
        }
        else {
            this.creationBacktrace = null;
        }
    }


    /**
     * @return the fid
     * @throws SmbException
     */
    public int getFid () throws SmbException {
        if ( !isValid() ) {
            throw new SmbException("Descriptor is no longer valid");
        }
        return this.fid;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileHandle#getTree()
     */
    @Override
    public SmbTreeHandleImpl getTree () {
        return this.tree.acquire();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileHandle#isValid()
     */
    @Override
    public boolean isValid () {
        return this.open && this.tree_num == this.tree.getTreeId() && this.tree.isConnected();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileHandle#close(long)
     */
    @Override
    public synchronized void close ( long lastWriteTime ) throws SmbException {
        closeInternal(lastWriteTime, true);
    }


    /**
     * @param lastWriteTime
     * @throws SmbException
     */
    void closeInternal ( long lastWriteTime, boolean explicit ) throws SmbException {
        SmbTreeHandleImpl t = this.tree;
        try {
            if ( t != null && isValid() ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Closing file handle " + this);
                }
                t.send(new SmbComClose(this.cfg, this.fid, lastWriteTime), new SmbComBlankResponse(this.cfg));
            }
        }
        finally {
            this.open = false;
            if ( t != null ) {
                // release tree usage
                t.release();
            }
            this.tree = null;
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbFileHandle#close()
     */
    @Override
    public void close () throws SmbException {
        release();
    }


    /**
     * {@inheritDoc}
     * 
     * @throws SmbException
     *
     * @see jcifs.smb.SmbFileHandle#release()
     */
    @Override
    public synchronized void release () throws SmbException {
        long usage = this.usageCount.decrementAndGet();
        if ( usage == 0 ) {
            closeInternal(0L, false);
        }
        else if ( log.isDebugEnabled() ) {
            log.debug(String.format("Release %s (%d)", this, usage));
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize () throws Throwable {
        if ( this.usageCount.get() != 0 && this.open ) {
            log.warn("File handle was not properly closed: " + this);
            if ( this.creationBacktrace != null ) {
                log.warn(Arrays.toString(this.creationBacktrace));
            }
        }
    }


    /**
     * @return a file handle with increased usage count
     */
    public SmbFileHandleImpl acquire () {
        long usage = this.usageCount.incrementAndGet();
        if ( log.isDebugEnabled() ) {
            log.debug(String.format("Acquire %s (%d)", this, usage));
        }
        return this;
    }


    /**
     * 
     */
    public void markClosed () {
        this.open = false;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        return String.format(
            "FileHandle %s [fid=%d,tree=%d,flags=%x,access=%x,attrs=%x,options=%x]",
            this.unc,
            this.fid,
            this.tree_num,
            this.flags,
            this.access,
            this.attrs,
            this.options);
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode () {
        return (int) ( this.fid + 3 * this.tree_num );
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals ( Object obj ) {
        if ( ! ( obj instanceof SmbFileHandleImpl ) ) {
            return false;
        }
        SmbFileHandleImpl o = (SmbFileHandleImpl) obj;
        return this.fid == o.fid && this.tree_num == o.tree_num;
    }

}
