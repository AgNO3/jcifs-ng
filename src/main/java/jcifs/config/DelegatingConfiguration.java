/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs.config;


import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.List;
import java.util.TimeZone;

import jcifs.Configuration;
import jcifs.ResolverType;


/**
 * @author mbechler
 *
 */
public class DelegatingConfiguration implements Configuration {

    private final Configuration delegate;


    /**
     * 
     */
    public DelegatingConfiguration ( Configuration delegate ) {
        this.delegate = delegate;
    }


    /**
     * @return
     * @see jcifs.Configuration#getRandom()
     */
    @Override
    public SecureRandom getRandom () {
        return this.delegate.getRandom();
    }


    /**
     * @return
     * @see jcifs.Configuration#getDfsTtl()
     */
    @Override
    public long getDfsTtl () {
        return this.delegate.getDfsTtl();
    }


    /**
     * @return
     * @see jcifs.Configuration#isDfsStrictView()
     */
    @Override
    public boolean isDfsStrictView () {
        return this.delegate.isDfsStrictView();
    }


    /**
     * @return
     * @see jcifs.Configuration#isDfsDisabled()
     */
    @Override
    public boolean isDfsDisabled () {
        return this.delegate.isDfsDisabled();
    }


    /**
     * @return
     * @see jcifs.Configuration#isForceUnicode()
     */
    @Override
    public boolean isForceUnicode () {
        return this.delegate.isForceUnicode();
    }


    /**
     * @return
     * @see jcifs.Configuration#isUseUnicode()
     */
    @Override
    public boolean isUseUnicode () {
        return this.delegate.isUseUnicode();
    }


    /**
     * @return
     * @see jcifs.Configuration#isUseBatching()
     */
    @Override
    public boolean isUseBatching () {
        return this.delegate.isUseBatching();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNativeOs()
     */
    @Override
    public String getNativeOs () {
        return this.delegate.getNativeOs();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNativeLanman()
     */
    @Override
    public String getNativeLanman () {
        return this.delegate.getNativeLanman();
    }


    /**
     * @return
     * @see jcifs.Configuration#getRecieveBufferSize()
     */
    @Override
    public int getRecieveBufferSize () {
        return this.delegate.getRecieveBufferSize();
    }


    /**
     * @return
     * @see jcifs.Configuration#getSendBufferSize()
     */
    @Override
    public int getSendBufferSize () {
        return this.delegate.getSendBufferSize();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getNotifyBufferSize()
     */
    @Override
    public int getNotifyBufferSize () {
        return this.delegate.getNotifyBufferSize();
    }


    /**
     * @return
     * @see jcifs.Configuration#getSoTimeout()
     */
    @Override
    public int getSoTimeout () {
        return this.delegate.getSoTimeout();
    }


    /**
     * @return
     * @see jcifs.Configuration#getResponseTimeout()
     */
    @Override
    public int getResponseTimeout () {
        return this.delegate.getResponseTimeout();
    }


    /**
     * @return
     * @see jcifs.Configuration#isTcpNoDelay()
     */
    @Override
    public boolean isTcpNoDelay () {
        return this.delegate.isTcpNoDelay();
    }


    /**
     * @return
     * @see jcifs.Configuration#getConnTimeout()
     */
    @Override
    public int getConnTimeout () {
        return this.delegate.getConnTimeout();
    }


    /**
     * @return
     * @see jcifs.Configuration#getLocalPort()
     */
    @Override
    public int getLocalPort () {
        return this.delegate.getLocalPort();
    }


    /**
     * @return
     * @see jcifs.Configuration#getLocalAddr()
     */
    @Override
    public InetAddress getLocalAddr () {
        return this.delegate.getLocalAddr();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosHostname()
     */
    @Override
    public String getNetbiosHostname () {
        return this.delegate.getNetbiosHostname();
    }


    /**
     * @return
     * @see jcifs.Configuration#getLogonShare()
     */
    @Override
    public String getLogonShare () {
        return this.delegate.getLogonShare();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosCacheTimeout()
     */
    @Override
    public int getNetbiosCacheTimeout () {
        return this.delegate.getNetbiosCacheTimeout();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosLookupRespLimit()
     */
    @Override
    public int getNetbiosLookupRespLimit () {
        return this.delegate.getNetbiosLookupRespLimit();
    }


    /**
     * @return
     * @see jcifs.Configuration#getDefaultDomain()
     */
    @Override
    public String getDefaultDomain () {
        return this.delegate.getDefaultDomain();
    }


    /**
     * @return
     * @see jcifs.Configuration#getDefaultUsername()
     */
    @Override
    public String getDefaultUsername () {
        return this.delegate.getDefaultUsername();
    }


    /**
     * @return
     * @see jcifs.Configuration#getDefaultPassword()
     */
    @Override
    public String getDefaultPassword () {
        return this.delegate.getDefaultPassword();
    }


    /**
     * @return
     * @see jcifs.Configuration#isDisablePlainTextPasswords()
     */
    @Override
    public boolean isDisablePlainTextPasswords () {
        return this.delegate.isDisablePlainTextPasswords();
    }


    /**
     * @return
     * @see jcifs.Configuration#getLanManCompatibility()
     */
    @Override
    public int getLanManCompatibility () {
        return this.delegate.getLanManCompatibility();
    }


    /**
     * @return
     * @see jcifs.Configuration#getResolveOrder()
     */
    @Override
    public List<ResolverType> getResolveOrder () {
        return this.delegate.getResolveOrder();
    }


    /**
     * @return
     * @see jcifs.Configuration#getBroadcastAddress()
     */
    @Override
    public InetAddress getBroadcastAddress () {
        return this.delegate.getBroadcastAddress();
    }


    /**
     * @return
     * @see jcifs.Configuration#getWinsServers()
     */
    @Override
    public InetAddress[] getWinsServers () {
        return this.delegate.getWinsServers();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosLocalPort()
     */
    @Override
    public int getNetbiosLocalPort () {
        return this.delegate.getNetbiosLocalPort();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosLocalAddress()
     */
    @Override
    public InetAddress getNetbiosLocalAddress () {
        return this.delegate.getNetbiosLocalAddress();
    }


    /**
     * @return
     * @see jcifs.Configuration#getVcNumber()
     */
    @Override
    public int getVcNumber () {
        return this.delegate.getVcNumber();
    }


    /**
     * @return
     * @see jcifs.Configuration#getCapabilities()
     */
    @Override
    public int getCapabilities () {
        return this.delegate.getCapabilities();
    }


    /**
     * @return
     * @see jcifs.Configuration#getFlags2()
     */
    @Override
    public int getFlags2 () {
        return this.delegate.getFlags2();
    }


    /**
     * @return
     * @see jcifs.Configuration#getSessionLimit()
     */
    @Override
    public int getSessionLimit () {
        return this.delegate.getSessionLimit();
    }


    /**
     * @return
     * @see jcifs.Configuration#getOemEncoding()
     */
    @Override
    public String getOemEncoding () {
        return this.delegate.getOemEncoding();
    }


    /**
     * @return
     * @see jcifs.Configuration#getLocalTimezone()
     */
    @Override
    public TimeZone getLocalTimezone () {
        return this.delegate.getLocalTimezone();
    }


    /**
     * @return
     * @see jcifs.Configuration#getPid()
     */
    @Override
    public int getPid () {
        return this.delegate.getPid();
    }


    /**
     * @return
     * @see jcifs.Configuration#getMaxMpxCount()
     */
    @Override
    public int getMaxMpxCount () {
        return this.delegate.getMaxMpxCount();
    }


    /**
     * @return
     * @see jcifs.Configuration#isSigningPreferred()
     */
    @Override
    public boolean isSigningPreferred () {
        return this.delegate.isSigningPreferred();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isSigningEnforced()
     */
    @Override
    public boolean isSigningEnforced () {
        return this.delegate.isSigningEnforced();
    }


    /**
     * @return
     * @see jcifs.Configuration#getLmHostsFileName()
     */
    @Override
    public String getLmHostsFileName () {
        return this.delegate.getLmHostsFileName();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosDefaultScope()
     */
    @Override
    public String getNetbiosScope () {
        return this.delegate.getNetbiosScope();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosDefaultSoTimeout()
     */
    @Override
    public int getNetbiosSoTimeout () {
        return this.delegate.getNetbiosSoTimeout();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosSndBufSize()
     */
    @Override
    public int getNetbiosSndBufSize () {
        return this.delegate.getNetbiosSndBufSize();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosRetryTimeout()
     */
    @Override
    public int getNetbiosRetryTimeout () {
        return this.delegate.getNetbiosRetryTimeout();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosRetryCount()
     */
    @Override
    public int getNetbiosRetryCount () {
        return this.delegate.getNetbiosRetryCount();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosRcvBufSize()
     */
    @Override
    public int getNetbiosRcvBufSize () {
        return this.delegate.getNetbiosRcvBufSize();
    }


    /**
     * @return
     * @see jcifs.Configuration#getNetbiosCachePolicy()
     */
    @Override
    public int getNetbiosCachePolicy () {
        return this.delegate.getNetbiosCachePolicy();
    }


    /**
     * @return
     * @see jcifs.Configuration#getTransactionBufferSize()
     */
    @Override
    public int getTransactionBufferSize () {
        return this.delegate.getTransactionBufferSize();
    }


    /**
     * @return
     * @see jcifs.Configuration#getBufferCacheSize()
     */
    @Override
    public int getBufferCacheSize () {
        return this.delegate.getBufferCacheSize();
    }


    /**
     * @return
     * @see jcifs.Configuration#getListCount()
     */
    @Override
    public int getListCount () {
        return this.delegate.getListCount();
    }


    /**
     * @return
     * @see jcifs.Configuration#getListSize()
     */
    @Override
    public int getListSize () {
        return this.delegate.getListSize();
    }


    /**
     * @return
     * @see jcifs.Configuration#getAttributeExpirationPeriod()
     */
    @Override
    public long getAttributeExpirationPeriod () {
        return this.delegate.getAttributeExpirationPeriod();
    }


    /**
     * @return
     * @see jcifs.Configuration#isIgnoreCopyToException()
     */
    @Override
    public boolean isIgnoreCopyToException () {
        return this.delegate.isIgnoreCopyToException();
    }


    /**
     * @param cmd
     * @return
     * @see jcifs.Configuration#getBatchLimit(java.lang.String)
     */
    @Override
    public int getBatchLimit ( String cmd ) {
        return this.delegate.getBatchLimit(cmd);
    }


    /**
     * @return
     * @see jcifs.Configuration#getSupportedDialects()
     */
    @Override
    public String[] getSupportedDialects () {
        return this.delegate.getSupportedDialects();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getMaxRequestRetries()
     */
    @Override
    public int getMaxRequestRetries () {
        return this.delegate.getMaxRequestRetries();
    }

}
