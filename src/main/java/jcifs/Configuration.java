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

    /**
     * 
     * @return random source to use
     */
    SecureRandom getRandom ();


    /**
     * 
     * @return title to live, in seconds, for DFS cache entries
     */
    long getDfsTtl ();


    /**
     * 
     * @return whether a authentication failure during DFS resolving will throw an exception
     */
    boolean isDfsStrictView ();


    /**
     * 
     * @return whether DFS lookup is disabled
     */
    boolean isDfsDisabled ();


    /**
     * 
     * @return whether to announce support for unicode
     */
    boolean isUseUnicode ();


    /**
     * 
     * @return whether to use unicode, even if the server does not announce it
     */
    boolean isForceUnicode ();


    /**
     * 
     * @return whether to use SMB1 AndX command batching
     */
    boolean isUseBatching ();


    /**
     * 
     * @return OS string to report
     */
    String getNativeOs ();


    /**
     * 
     * @return Lanman string to report
     */
    String getNativeLanman ();


    /**
     * 
     * @return recieve buffer size, in bytes
     */
    int getRecieveBufferSize ();


    /**
     * 
     * @return send buffer size, in bytes
     */
    int getSendBufferSize ();


    /**
     * 
     * @return socket timeout, in milliseconds
     */
    int getSoTimeout ();


    /**
     * 
     * @return timeout for establishing a socket connection, in milliseconds
     */
    int getConnTimeout ();


    /**
     * @return timeout for SMB sessions, in milliseconds
     */
    int getSessionTimeout ();


    /**
     * 
     * @return timeout for SMB responses, in milliseconds
     */
    int getResponseTimeout ();


    /**
     * 
     * @return local port to use for outgoing connections
     */
    int getLocalPort ();


    /**
     * 
     * @return local address to use for outgoing connections
     */
    InetAddress getLocalAddr ();


    /**
     * 
     * @return local NETBIOS/short name to announce
     */
    String getNetbiosHostname ();


    /**
     * @return share to connect to during authentication, if unset connect to IPC$
     */
    String getLogonShare ();


    /**
     * @return default credentials, domain name
     */
    String getDefaultDomain ();


    /**
     * @return default credentials, user name
     */
    String getDefaultUsername ();


    /**
     * @return default credentials, password
     */
    String getDefaultPassword ();


    /**
     * Lanman compatibility level
     * 
     * {@href https://technet.microsoft.com/en-us/library/cc960646.aspx}
     * 
     * <table summary="values">
     * <tr>
     * <td>0 or 1</td>
     * <td>LM and NTLM</td>
     * </tr>
     * <tr>
     * <td>2</td>
     * <td>NTLM only</td>
     * </tr>
     * <tr>
     * <td>3-5</td>
     * <td>NTLMv2 only</td>
     * </table>
     * 
     * @return lanman compatibility level, defaults to 3
     */
    int getLanManCompatibility ();


    /**
     * @return whether the usage of plaintext passwords is prohibited, defaults to false
     */
    boolean isDisablePlainTextPasswords ();


    /**
     * @return order and selection of resolver modules, see {@link ResolverType}
     */
    List<ResolverType> getResolveOrder ();


    /**
     * @return broadcast address to use
     */
    InetAddress getBroadcastAddress ();


    /**
     * @return WINS server to use
     */
    InetAddress[] getWinsServers ();


    /**
     * @return local bind port for nebios connections
     */
    int getNetbiosLocalPort ();


    /**
     * @return local bind address for netbios connections
     */
    InetAddress getNetbiosLocalAddress ();


    /**
     * @return socket timeout for netbios connections
     */
    int getNetbiosSoTimeout ();


    /**
     * @return virtual circuit number to use
     */
    int getVcNumber ();


    /**
     * @return custom capabilities
     */
    int getCapabilities ();


    /**
     * @return custom flags2
     */
    int getFlags2 ();


    /**
     * @return maximum number of sessions on a single connection
     */
    int getSessionLimit ();


    /**
     * @return OEM encoding to use
     */
    String getOemEncoding ();


    /**
     * @return local timezone
     */
    TimeZone getLocalTimezone ();


    /**
     * @return Process id to send, randomized if unset
     */
    int getPid ();


    /**
     * @return maximum count of concurrent commands to announce
     */
    int getMaxMpxCount ();


    /**
     * @return whether to enable SMB signing, if available
     */
    boolean isSigningEnabled ();


    /**
     * @return whether to enforce SMB signing
     */
    boolean isSigningEnforced ();


    /**
     * @return lmhosts file to use
     */
    String getLmHostsFileName ();


    /**
     * @return default netbios scope to set in requests
     */
    String getNetbiosScope ();


    /**
     * 
     * @return netbios send buffer size
     */
    int getNetbiosSndBufSize ();


    /**
     * 
     * @return netbios recieve buffer size
     */
    int getNetbiosRcvBufSize ();


    /**
     * 
     * @return timeout of retry requests, in milliseconds
     */
    int getNetbiosRetryTimeout ();


    /**
     * 
     * @return maximum number of retries for netbios requests
     */
    int getNetbiosRetryCount ();


    /**
     * @return netbios cache timeout, in seconds, 0 - disable caching, -1 - cache forever
     */
    int getNetbiosCachePolicy ();


    /**
     * @return maximum data size for SMB transactions
     */
    int getTransactionBufferSize ();


    /**
     * @return number of buffers to keep in cache
     */
    int getBufferCacheSize ();


    /**
     * @return maxmimum number of elements to request in a list request
     */
    int getListCount ();


    /**
     * @return maximum data size for list requests
     */
    int getListSize ();


    /**
     * @return timeout of file attribute cache
     */
    long getAttributeCacheTimeout ();


    /**
     * @return whether to ignore exceptions
     */
    boolean isIgnoreCopyToException ();


    /**
     * @param cmd
     * @return the batch limit for the given command
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
