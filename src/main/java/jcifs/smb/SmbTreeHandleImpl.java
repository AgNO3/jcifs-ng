/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 14.03.2017 by mbechler
 */
package jcifs.smb;


import jcifs.Configuration;


/**
 * @author mbechler
 *
 */
public class SmbTreeHandleImpl implements AutoCloseable, SmbTreeHandle {

    private final SmbFileLocator resourceLoc;
    private final SmbTreeConnection treeConnection;


    /**
     * @param resourceLoc
     * @param treeConnection
     */
    public SmbTreeHandleImpl ( SmbFileLocator resourceLoc, SmbTreeConnection treeConnection ) {
        this.resourceLoc = resourceLoc;
        this.treeConnection = treeConnection;
    }


    /**
     * Internal/testing use only
     * 
     * @return attached session
     */
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
        return this.treeConnection.getSession().getConfig();
    }


    /**
     * @return the currently connected tree id
     */
    public int getTreeId () {
        return this.treeConnection.getTreeId();
    }


    /**
     * @param request
     * @param response
     * @throws SmbException
     */
    public void send ( ServerMessageBlock request, ServerMessageBlock response ) throws SmbException {
        this.treeConnection.send(this.resourceLoc, request, response);
    }


    /**
     * 
     * @param request
     * @param response
     * @param timeout
     * @throws SmbException
     */
    public void send ( ServerMessageBlock request, ServerMessageBlock response, boolean timeout ) throws SmbException {
        this.treeConnection.send(this.resourceLoc, request, response, timeout);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#close()
     */
    @Override
    public void close () throws SmbException {
        release();
    }


    /**
     * @return tree handle with increased usage count
     */
    public SmbTreeHandleImpl acquire () {
        return this;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#release()
     */
    @Override
    public void release () {

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
        return this.treeConnection.getSession().getTransport().snd_buf_size;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeHandle#getReceiveBufferSize()
     */
    @Override
    public int getReceiveBufferSize () {
        return this.treeConnection.getSession().getTransport().rcv_buf_size;
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
        SmbSession session = this.treeConnection.getSession();
        return session.getTransport().server.signaturesRequired
                || ( session.getTransport().server.signaturesEnabled && this.getConfig().isSigningEnabled() );
    }

}
