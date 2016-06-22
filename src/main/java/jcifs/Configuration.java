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
package jcifs;


import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.List;
import java.util.TimeZone;


/**
 * @author mbechler
 *
 */
public interface Configuration {

    SecureRandom getRandom ();


    long getDfsTtl ();


    boolean isDfsStrictView ();


    boolean isDfsDisabled ();


    boolean isForceUnicode ();


    boolean isUseUnicode ();


    boolean isUseBatching ();


    String getNativeOs ();


    String getNativeLanman ();


    int getRecieveBufferSize ();


    int getSendBufferSize ();


    int getSoTimeout ();


    int getResponseTimeout ();


    boolean isTcpNoDelay ();


    int getConnTimeout ();


    int getLocalPort ();


    InetAddress getLocalAddr ();


    String getNetbiosHostname ();


    /**
     * @return
     */
    String getLogonShare ();


    /**
     * @return
     */
    int getNetbiosCacheTimeout ();


    /**
     * @return
     */
    int getNetbiosLookupRespLimit ();


    /**
     * @return
     */
    String getDefaultDomain ();


    /**
     * @return
     */
    String getDefaultUsername ();


    /**
     * @return
     */
    String getDefaultPassword ();


    /**
     * @return
     */
    boolean isDisablePlainTextPasswords ();


    /**
     * @return
     */
    int getLanManCompatibility ();


    /**
     * @return
     */
    List<ResolverType> getResolveOrder ();


    /**
     * @return
     */
    InetAddress getBroadcastAddress ();


    /**
     * @return
     */
    InetAddress[] getWinsServers ();


    /**
     * @return
     */
    int getNetbiosLocalPort ();


    /**
     * @return
     */
    InetAddress getNetbiosLocalAddress ();


    /**
     * @return
     */
    int getNetbiosSoTimeout ();


    /**
     * @return
     */
    int getVcNumber ();


    /**
     * @return
     */
    int getCapabilities ();


    /**
     * @return
     */
    int getFlags2 ();


    /**
     * @return
     */
    int getSessionLimit ();


    /**
     * @return
     */
    String getOemEncoding ();


    /**
     * @return
     */
    TimeZone getLocalTimezone ();


    /**
     * @return
     */
    int getPid ();


    /**
     * @return
     */
    int getMaxMpxCount ();


    /**
     * @return
     */
    boolean isSigningPreferred ();


    /**
     * @return
     */
    boolean isSigningEnforced ();


    /**
     * @return
     */
    String getLmHostsFileName ();


    /**
     * @return
     */
    String getNetbiosScope ();


    int getNetbiosSndBufSize ();


    int getNetbiosRetryTimeout ();


    int getNetbiosRetryCount ();


    int getNetbiosRcvBufSize ();


    /**
     * @return
     */
    int getNetbiosCachePolicy ();


    /**
     * @return
     */
    int getTransactionBufferSize ();


    /**
     * @return
     */
    int getBufferCacheSize ();


    /**
     * @return
     */
    int getListCount ();


    /**
     * @return
     */
    int getListSize ();


    /**
     * @return
     */
    long getAttributeExpirationPeriod ();


    /**
     * @return
     */
    boolean isIgnoreCopyToException ();


    /**
     * @param string
     * @return
     */
    int getBatchLimit ( String cmd );


    /**
     * @return the supported dialects
     */
    String[] getSupportedDialects ();


    /**
     * @return the size of the requested server notify buffer
     */
    int getNotifyBufferSize ();


    /**
     * @return retry SMB requests on failure up to n times
     */
    int getMaxRequestRetries ();

}
