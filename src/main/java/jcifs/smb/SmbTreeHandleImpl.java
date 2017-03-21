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


import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.smb.SmbTransport.ServerData;


/**
 * @author mbechler
 *
 */
class SmbTreeHandleImpl implements SmbTreeHandle {

    private static final Logger log = LoggerFactory.getLogger(SmbTreeHandleImpl.class);

    private final SmbFileLocatorImpl resourceLoc;
    private final SmbTreeConnection treeConnection;

    private final AtomicLong usageCount = new AtomicLong(1);


    /**
     * @param resourceLoc
     * @param treeConnection
     */
    public SmbTreeHandleImpl ( SmbFileLocatorImpl resourceLoc, SmbTreeConnection treeConnection ) {
        this.resourceLoc = resourceLoc;
        this.treeConnection = treeConnection.acquire();
    }


    /**
     * Internal/testing use only
     * 
     * @return attached session
     */
    @Override
    public SmbSession getSession () {
        return this.treeConnection.getSession();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#ensureDFSResolved()
     */
    @Override
    public void ensureDFSResolved () throws SmbException {
        this.treeConnection.ensureDFSResolved(this.resourceLoc);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#hasCapability(int)
     */
    @Override
    public boolean hasCapability ( int cap ) throws SmbException {
        return this.treeConnection.hasCapability(cap);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#isConnected()
     */
    @Override
    public boolean isConnected () {
        return this.treeConnection.isConnected();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#getConfig()
     */
    @Override
    public Configuration getConfig () {
        return this.treeConnection.getConfig();
    }


    /**
     * @return the currently connected tree id
     */
    public long getTreeId () {
        return this.treeConnection.getTreeId();
    }


    /**
     * @param request
     * @param response
     * @param params
     * @throws SmbException
     */
    public void send ( ServerMessageBlock request, ServerMessageBlock response, RequestParam... params ) throws SmbException {
        this.treeConnection.send(this.resourceLoc, request, response);
    }


    /**
     * 
     * @param request
     * @param response
     * @param params
     * @throws SmbException
     */
    public void send ( ServerMessageBlock request, ServerMessageBlock response, Set<RequestParam> params ) throws SmbException {
        this.treeConnection.send(this.resourceLoc, request, response, params);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#close()
     */
    @Override
    public synchronized void close () {
        release();
    }


    /**
     * @return tree handle with increased usage count
     */
    public SmbTreeHandleImpl acquire () {
        if ( this.usageCount.incrementAndGet() == 1 ) {
            this.treeConnection.acquire();
        }
        return this;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#release()
     */
    @Override
    public void release () {
        long us = this.usageCount.decrementAndGet();
        if ( us == 0 ) {
            this.treeConnection.release();
        }
        else if ( us < 0 ) {
            throw new RuntimeCIFSException("Usage count dropped below zero");
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize () throws Throwable {
        if ( this.usageCount.get() != 0 ) {
            log.warn("Tree handle was not properly released " + this.resourceLoc.getURL());
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#getServerTimeZoneOffset()
     */
    @Override
    public long getServerTimeZoneOffset () {
        return this.treeConnection.getServerData().serverTimeZone * 1000 * 60L;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#getOEMDomainName()
     */
    @Override
    public String getOEMDomainName () {
        return this.treeConnection.getServerData().oemDomainName;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#getConnectedService()
     */
    @Override
    public String getConnectedService () {
        return this.treeConnection.getConnectedService();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#getConnectedShare()
     */
    @Override
    public String getConnectedShare () {
        return this.treeConnection.getConnectedShare();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#isSameTree(jcifs.smb.SmbTreeHandleImpl)
     */
    @Override
    public boolean isSameTree ( SmbTreeHandleImpl th ) {
        return this.treeConnection.isSame(th.treeConnection);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#getSendBufferSize()
     */
    @Override
    public int getSendBufferSize () {
        try ( SmbSession session = this.treeConnection.getSession();
              SmbTransport transport = session.getTransport() ) {
            return transport.snd_buf_size;
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#getReceiveBufferSize()
     */
    @Override
    public int getReceiveBufferSize () {
        try ( SmbSession session = this.treeConnection.getSession();
              SmbTransport transport = session.getTransport() ) {
            return transport.rcv_buf_size;
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#getMaximumBufferSize()
     */
    @Override
    public int getMaximumBufferSize () {
        return this.treeConnection.getServerData().maxBufferSize;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#areSignaturesActive()
     */
    @Override
    public boolean areSignaturesActive () {
        ServerData serverData = this.treeConnection.getServerData();
        return serverData.signaturesRequired || ( serverData.signaturesEnabled && getConfig().isSigningEnabled() );
    }

}
