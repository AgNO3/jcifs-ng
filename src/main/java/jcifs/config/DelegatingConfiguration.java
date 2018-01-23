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
import jcifs.DialectVersion;
import jcifs.ResolverType;


/**
 * @author mbechler
 *
 */
public class DelegatingConfiguration implements Configuration {

    private final Configuration delegate;


    /**
     * @param delegate
     *            delegate to pass all non-overridden method calls to
     * 
     */
    public DelegatingConfiguration ( Configuration delegate ) {
        this.delegate = delegate;
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getRandom()
     */
    @Override
    public SecureRandom getRandom () {
        return this.delegate.getRandom();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getMinimumVersion()
     */
    @Override
    public DialectVersion getMinimumVersion () {
        return this.delegate.getMinimumVersion();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getMaximumVersion()
     */
    @Override
    public DialectVersion getMaximumVersion () {
        return this.delegate.getMaximumVersion();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isUseSMB2OnlyNegotiation()
     */
    @Override
    public boolean isUseSMB2OnlyNegotiation () {
        return this.delegate.isUseSMB2OnlyNegotiation();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isRequireSecureNegotiate()
     */
    @Override
    public boolean isRequireSecureNegotiate () {
        return this.delegate.isRequireSecureNegotiate();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isPort139FailoverEnabled()
     */
    @Override
    public boolean isPort139FailoverEnabled () {
        return this.delegate.isPort139FailoverEnabled();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getDfsTtl()
     */
    @Override
    public long getDfsTtl () {
        return this.delegate.getDfsTtl();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#isDfsStrictView()
     */
    @Override
    public boolean isDfsStrictView () {
        return this.delegate.isDfsStrictView();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#isDfsDisabled()
     */
    @Override
    public boolean isDfsDisabled () {
        return this.delegate.isDfsDisabled();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isDfsConvertToFQDN()
     */
    @Override
    public boolean isDfsConvertToFQDN () {
        return this.delegate.isDfsConvertToFQDN();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#isForceUnicode()
     */
    @Override
    public boolean isForceUnicode () {
        return this.delegate.isForceUnicode();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#isUseUnicode()
     */
    @Override
    public boolean isUseUnicode () {
        return this.delegate.isUseUnicode();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#isUseBatching()
     */
    @Override
    public boolean isUseBatching () {
        return this.delegate.isUseBatching();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNativeOs()
     */
    @Override
    public String getNativeOs () {
        return this.delegate.getNativeOs();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNativeLanman()
     */
    @Override
    public String getNativeLanman () {
        return this.delegate.getNativeLanman();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getMaximumBufferSize()
     */
    @Override
    public int getMaximumBufferSize () {
        return this.delegate.getMaximumBufferSize();
    }


    /**
     * {@inheritDoc}
     * 
     * @deprecated use getReceiveBufferSize instead
     */
    @Deprecated
    @Override
    public int getRecieveBufferSize () {
        return this.delegate.getReceiveBufferSize();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getReceiveBufferSize()
     */
    @Override
    public int getReceiveBufferSize () {
        return this.delegate.getReceiveBufferSize();
    }


    /**
     * {@inheritDoc}
     * 
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
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getSoTimeout()
     */
    @Override
    public int getSoTimeout () {
        return this.delegate.getSoTimeout();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getResponseTimeout()
     */
    @Override
    public int getResponseTimeout () {
        return this.delegate.getResponseTimeout();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getConnTimeout()
     */
    @Override
    public int getConnTimeout () {
        return this.delegate.getConnTimeout();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getSessionTimeout()
     */
    @Override
    public int getSessionTimeout () {
        return this.delegate.getSessionTimeout();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getLocalPort()
     */
    @Override
    public int getLocalPort () {
        return this.delegate.getLocalPort();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getLocalAddr()
     */
    @Override
    public InetAddress getLocalAddr () {
        return this.delegate.getLocalAddr();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNetbiosHostname()
     */
    @Override
    public String getNetbiosHostname () {
        return this.delegate.getNetbiosHostname();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getLogonShare()
     */
    @Override
    public String getLogonShare () {
        return this.delegate.getLogonShare();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getDefaultDomain()
     */
    @Override
    public String getDefaultDomain () {
        return this.delegate.getDefaultDomain();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getDefaultUsername()
     */
    @Override
    public String getDefaultUsername () {
        return this.delegate.getDefaultUsername();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getDefaultPassword()
     */
    @Override
    public String getDefaultPassword () {
        return this.delegate.getDefaultPassword();
    }


    /**
     * 
     * @see jcifs.Configuration#isDisablePlainTextPasswords()
     */
    @Override
    public boolean isDisablePlainTextPasswords () {
        return this.delegate.isDisablePlainTextPasswords();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isForceExtendedSecurity()
     */
    @Override
    public boolean isForceExtendedSecurity () {
        return this.delegate.isForceExtendedSecurity();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getLanManCompatibility()
     */
    @Override
    public int getLanManCompatibility () {
        return this.delegate.getLanManCompatibility();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isAllowNTLMFallback()
     */
    @Override
    public boolean isAllowNTLMFallback () {
        return this.delegate.isAllowNTLMFallback();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isUseRawNTLM()
     */
    @Override
    public boolean isUseRawNTLM () {
        return this.delegate.isUseRawNTLM();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isDisableSpnegoIntegrity()
     */
    @Override
    public boolean isDisableSpnegoIntegrity () {
        return this.delegate.isDisableSpnegoIntegrity();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isEnforceSpnegoIntegrity()
     */
    @Override
    public boolean isEnforceSpnegoIntegrity () {
        return this.delegate.isEnforceSpnegoIntegrity();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getResolveOrder()
     */
    @Override
    public List<ResolverType> getResolveOrder () {
        return this.delegate.getResolveOrder();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getBroadcastAddress()
     */
    @Override
    public InetAddress getBroadcastAddress () {
        return this.delegate.getBroadcastAddress();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getWinsServers()
     */
    @Override
    public InetAddress[] getWinsServers () {
        return this.delegate.getWinsServers();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNetbiosLocalPort()
     */
    @Override
    public int getNetbiosLocalPort () {
        return this.delegate.getNetbiosLocalPort();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNetbiosLocalAddress()
     */
    @Override
    public InetAddress getNetbiosLocalAddress () {
        return this.delegate.getNetbiosLocalAddress();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getVcNumber()
     */
    @Override
    public int getVcNumber () {
        return this.delegate.getVcNumber();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getCapabilities()
     */
    @Override
    public int getCapabilities () {
        return this.delegate.getCapabilities();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getFlags2()
     */
    @Override
    public int getFlags2 () {
        return this.delegate.getFlags2();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getSessionLimit()
     */
    @Override
    public int getSessionLimit () {
        return this.delegate.getSessionLimit();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getOemEncoding()
     */
    @Override
    public String getOemEncoding () {
        return this.delegate.getOemEncoding();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getLocalTimezone()
     */
    @Override
    public TimeZone getLocalTimezone () {
        return this.delegate.getLocalTimezone();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getPid()
     */
    @Override
    public int getPid () {
        return this.delegate.getPid();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getMaxMpxCount()
     */
    @Override
    public int getMaxMpxCount () {
        return this.delegate.getMaxMpxCount();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#isSigningEnabled()
     */
    @Override
    public boolean isSigningEnabled () {
        return this.delegate.isSigningEnabled();
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
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isIpcSigningEnforced()
     */
    @Override
    public boolean isIpcSigningEnforced () {
        return this.delegate.isIpcSigningEnforced();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isEncryptionEnabled()
     */
    @Override
    public boolean isEncryptionEnabled () {
        return this.delegate.isEncryptionEnabled();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getLmHostsFileName()
     */
    @Override
    public String getLmHostsFileName () {
        return this.delegate.getLmHostsFileName();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNetbiosScope()
     */
    @Override
    public String getNetbiosScope () {
        return this.delegate.getNetbiosScope();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNetbiosSoTimeout()
     */
    @Override
    public int getNetbiosSoTimeout () {
        return this.delegate.getNetbiosSoTimeout();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNetbiosSndBufSize()
     */
    @Override
    public int getNetbiosSndBufSize () {
        return this.delegate.getNetbiosSndBufSize();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNetbiosRetryTimeout()
     */
    @Override
    public int getNetbiosRetryTimeout () {
        return this.delegate.getNetbiosRetryTimeout();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNetbiosRetryCount()
     */
    @Override
    public int getNetbiosRetryCount () {
        return this.delegate.getNetbiosRetryCount();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNetbiosRcvBufSize()
     */
    @Override
    public int getNetbiosRcvBufSize () {
        return this.delegate.getNetbiosRcvBufSize();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getNetbiosCachePolicy()
     */
    @Override
    public int getNetbiosCachePolicy () {
        return this.delegate.getNetbiosCachePolicy();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getTransactionBufferSize()
     */
    @Override
    public int getTransactionBufferSize () {
        return this.delegate.getTransactionBufferSize();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getBufferCacheSize()
     */
    @Override
    public int getBufferCacheSize () {
        return this.delegate.getBufferCacheSize();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getListCount()
     */
    @Override
    public int getListCount () {
        return this.delegate.getListCount();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getListSize()
     */
    @Override
    public int getListSize () {
        return this.delegate.getListSize();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getAttributeCacheTimeout()
     */
    @Override
    public long getAttributeCacheTimeout () {
        return this.delegate.getAttributeCacheTimeout();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#isIgnoreCopyToException()
     */
    @Override
    public boolean isIgnoreCopyToException () {
        return this.delegate.isIgnoreCopyToException();
    }


    /**
     * {@inheritDoc}
     * 
     * @see jcifs.Configuration#getBatchLimit(java.lang.String)
     */
    @Override
    public int getBatchLimit ( String cmd ) {
        return this.delegate.getBatchLimit(cmd);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isAllowCompound(java.lang.String)
     */
    @Override
    public boolean isAllowCompound ( String command ) {
        return this.delegate.isAllowCompound(command);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isTraceResourceUsage()
     */
    @Override
    public boolean isTraceResourceUsage () {
        return this.delegate.isTraceResourceUsage();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isStrictResourceLifecycle()
     */
    @Override
    public boolean isStrictResourceLifecycle () {
        return this.delegate.isStrictResourceLifecycle();
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


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getMachineId()
     */
    @Override
    public byte[] getMachineId () {
        return this.delegate.getMachineId();
    }
}
