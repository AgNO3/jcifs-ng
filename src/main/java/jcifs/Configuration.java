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
 * 
 * 
 * Implementors of this interface should extend {@link jcifs.config.BaseConfiguration} or
 * {@link jcifs.config.DelegatingConfiguration} to get forward compatibility.
 * 
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
     * 
     * Property <tt>jcifs.smb.client.dfs.ttl</tt> (int, default 300)
     * 
     * @return title to live, in seconds, for DFS cache entries
     */
    long getDfsTtl ();


    /**
     * 
     * Property <tt>jcifs.smb.client.dfs.strictView</tt> (boolean, default false)
     * 
     * @return whether a authentication failure during DFS resolving will throw an exception
     */
    boolean isDfsStrictView ();


    /**
     * 
     * Property <tt>jcifs.smb.client.dfs.disabled</tt> (boolean, default false)
     * 
     * @return whether DFS lookup is disabled
     */
    boolean isDfsDisabled ();


    /**
     * Enable hack to make kerberos auth work with DFS sending short names
     * 
     * This works by appending the domain name to the netbios short name and will fail horribly if this mapping is not
     * correct for your domain.
     * 
     * Property <tt>jcifs.smb.client.dfs.convertToFQDN</tt> (boolean, default false)
     * 
     * @return whether to convert NetBIOS names returned by DFS to FQDNs
     */
    boolean isDfsConvertToFQDN ();


    /**
     * Minimum protocol version
     * 
     * Property <tt>jcifs.smb.client.minVersion</tt> (string, default SMB1)
     * 
     * @see DialectVersion
     * @return minimum protocol version to use/allow
     * @since 2.1
     */
    DialectVersion getMinimumVersion ();


    /**
     * Maximum protocol version
     * 
     * Property <tt>jcifs.smb.client.maxVersion</tt> (string, default SMB210)
     * 
     * @see DialectVersion
     * @return maximum protocol version to use/allow
     * @since 2.1
     */
    DialectVersion getMaximumVersion ();


    /**
     * Use SMB2 non-backward compatible negotiation style
     * 
     * Property <tt>jcifs.smb.client.useSMB2Negotiation</tt> (boolean, default false)
     * 
     * @return whether to use non-backward compatible protocol negotiation
     */
    boolean isUseSMB2OnlyNegotiation ();


    /**
     * Enforce secure negotiation
     * 
     * Property <tt>jcifs.smb.client.requireSecureNegotiate</tt> (boolean, default true)
     * 
     * This does not provide any actual downgrade protection if SMB1 is allowed.
     * 
     * It will also break connections with SMB2 servers that do not properly sign error responses.
     * 
     * @return whether to enforce the use of secure negotiation.
     */
    boolean isRequireSecureNegotiate ();


    /**
     * Enable port 139 failover
     * 
     * Property <tt>jcifs.smb.client.port139.enabled</tt> (boolean, default false)
     * 
     * @return whether to failover to legacy transport on port 139
     */
    boolean isPort139FailoverEnabled ();


    /**
     * 
     * Property <tt>jcifs.smb.client.useUnicode</tt> (boolean, default true)
     * 
     * @return whether to announce support for unicode
     */
    boolean isUseUnicode ();


    /**
     *
     * Property <tt>jcifs.smb.client.forceUnicode</tt> (boolean, default false)
     * 
     * @return whether to use unicode, even if the server does not announce it
     */
    boolean isForceUnicode ();


    /**
     * 
     * Property <tt>jcifs.smb.client.useBatching</tt> (boolean, default true)
     * 
     * @return whether to enable support for SMB1 AndX command batching
     */
    boolean isUseBatching ();


    /**
     * 
     * Property <tt>jcifs.smb.client.nativeOs</tt> (string, default <tt>os.name</tt>)
     * 
     * @return OS string to report
     */
    String getNativeOs ();


    /**
     * 
     * Property <tt>jcifs.smb.client.nativeLanMan</tt> (string, default <tt>jCIFS</tt>)
     * 
     * @return Lanman string to report
     */
    String getNativeLanman ();


    /**
     * 
     * Property <tt>jcifs.smb.client.rcv_buf_size</tt> (int, default 65535)
     * 
     * @return receive buffer size, in bytes
     * @deprecated use getReceiveBufferSize instead
     */
    @Deprecated
    int getRecieveBufferSize ();


    /**
     * 
     * Property <tt>jcifs.smb.client.rcv_buf_size</tt> (int, default 65535)
     * 
     * @return receive buffer size, in bytes
     */
    int getReceiveBufferSize ();


    /**
     * 
     * Property <tt>jcifs.smb.client.snd_buf_size</tt> (int, default 65535)
     * 
     * @return send buffer size, in bytes
     */
    int getSendBufferSize ();


    /**
     * 
     * Property <tt>jcifs.smb.client.soTimeout</tt> (int, default 35000)
     * 
     * @return socket timeout, in milliseconds
     */
    int getSoTimeout ();


    /**
     * 
     * Property <tt>jcifs.smb.client.connTimeout</tt> (int, default 35000)
     * 
     * @return timeout for establishing a socket connection, in milliseconds
     */
    int getConnTimeout ();


    /**
     * Property <tt>jcifs.smb.client.sessionTimeout</tt> (int, default 35000)
     * 
     * 
     * @return timeout for SMB sessions, in milliseconds
     */
    int getSessionTimeout ();


    /**
     * 
     * Property <tt>jcifs.smb.client.responseTimeout</tt> (int, default 30000)
     * 
     * @return timeout for SMB responses, in milliseconds
     */
    int getResponseTimeout ();


    /**
     * 
     * Property <tt>jcifs.smb.client.lport</tt> (int)
     * 
     * @return local port to use for outgoing connections
     */
    int getLocalPort ();


    /**
     * 
     * Property <tt>jcifs.smb.client.laddr</tt> (string)
     * 
     * @return local address to use for outgoing connections
     */
    InetAddress getLocalAddr ();


    /**
     * 
     * Property <tt>jcifs.netbios.hostname</tt> (string)
     * 
     * @return local NETBIOS/short name to announce
     */
    String getNetbiosHostname ();


    /**
     * 
     * Property <tt>jcifs.smb.client.logonShare</tt>
     * 
     * @return share to connect to during authentication, if unset connect to IPC$
     */
    String getLogonShare ();


    /**
     * 
     * 
     * Property <tt>jcifs.smb.client.domain</tt>
     * 
     * @return default credentials, domain name
     */
    String getDefaultDomain ();


    /**
     * 
     * Property <tt>jcifs.smb.client.username</tt>
     * 
     * @return default credentials, user name
     */
    String getDefaultUsername ();


    /**
     * 
     * Property <tt>jcifs.smb.client.password</tt>
     * 
     * @return default credentials, password
     */
    String getDefaultPassword ();


    /**
     * Lanman compatibility level
     * 
     * {@href https://technet.microsoft.com/en-us/library/cc960646.aspx}
     * 
     * 
     * <table>
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
     * </tr>
     * </table>
     * 
     * 
     * Property <tt>jcifs.smb.lmCompatibility</tt> (int, default 3)
     * 
     * @return lanman compatibility level, defaults to 3 i.e. NTLMv2 only
     */
    int getLanManCompatibility ();


    /**
     * 
     * Property <tt>jcifs.smb.allowNTLMFallback</tt> (boolean, default true)
     * 
     * @return whether to allow fallback from kerberos to NTLM
     */
    boolean isAllowNTLMFallback ();


    /**
     * Property <tt>jcifs.smb.useRawNTLM</tt> (boolean, default false)
     * 
     * @return whether to use raw NTLMSSP tokens instead of SPNEGO wrapped ones
     * @since 2.1
     */
    boolean isUseRawNTLM ();


    /**
     * 
     * Property <tt>jcifs.smb.client.disablePlainTextPasswords</tt> (boolean, default true)
     * 
     * @return whether the usage of plaintext passwords is prohibited, defaults to false
     */
    boolean isDisablePlainTextPasswords ();


    /**
     * 
     * 
     * Property <tt>jcifs.resolveOrder</tt> (string, default <tt>LMHOSTS,DNS,WINS,BCAST</tt>)
     * 
     * @return order and selection of resolver modules, see {@link ResolverType}
     */
    List<ResolverType> getResolveOrder ();


    /**
     * 
     * Property <tt>jcifs.netbios.baddr</tt> (string, default <tt>255.255.255.255</tt>)
     * 
     * @return broadcast address to use
     */
    InetAddress getBroadcastAddress ();


    /**
     * 
     * 
     * Property <tt>jcifs.netbios.wins</tt> (string, comma separated)
     * 
     * @return WINS server to use
     */
    InetAddress[] getWinsServers ();


    /**
     * 
     * Property <tt>jcifs.netbios.lport</tt> (int)
     * 
     * @return local bind port for nebios connections
     */
    int getNetbiosLocalPort ();


    /**
     * 
     * Property <tt>jcifs.netbios.laddr</tt> (string)
     * 
     * @return local bind address for netbios connections
     */
    InetAddress getNetbiosLocalAddress ();


    /**
     * 
     * 
     * Property <tt>jcifs.netbios.soTimeout</tt> (int, default 5000)
     * 
     * @return socket timeout for netbios connections, in milliseconds
     */
    int getNetbiosSoTimeout ();


    /**
     * 
     * 
     * @return virtual circuit number to use
     */
    int getVcNumber ();


    /**
     * 
     * Property <tt>jcifs.smb.client.capabilities</tt> (int)
     * 
     * @return custom capabilities
     */
    int getCapabilities ();


    /**
     * 
     * 
     * Property <tt>jcifs.smb.client.flags2</tt> (int)
     * 
     * @return custom flags2
     */
    int getFlags2 ();


    /**
     * 
     * Property <tt>jcifs.smb.client.ssnLimit</tt> (int, 250)
     * 
     * @return maximum number of sessions on a single connection
     */
    int getSessionLimit ();


    /**
     * 
     * Property <tt>jcifs.encoding</tt> (string, default <tt>Cp850</tt>)
     * 
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
     * 
     * Property <tt>jcifs.smb.client.maxMpxCount</tt> (int, default 10)
     * 
     * @return maximum count of concurrent commands to announce
     */
    int getMaxMpxCount ();


    /**
     * 
     * Property <tt>jcifs.smb.client.signingPreferred</tt> (boolean, default false)
     * 
     * @return whether to enable SMB signing (for everything), if available
     */
    boolean isSigningEnabled ();


    /**
     * 
     * Property <tt>jcifs.smb.client.ipcSigningEnforced</tt> (boolean, default true)
     * 
     * @return whether to enforce SMB signing for IPC connections
     */
    boolean isIpcSigningEnforced ();


    /**
     * 
     * Property <tt>jcifs.smb.client.signingEnforced</tt> (boolean, default false)
     * 
     * @return whether to enforce SMB signing (for everything)
     */
    boolean isSigningEnforced ();


    /**
     * Property <tt>jcifs.smb.client.encryptionEnabled</tt> (boolean, default false)
     * 
     * This is an experimental option allowing to indicate support during protocol
     * negotiation, SMB encryption is not implemented yet.
     * 
     * @return whether SMB encryption is enabled
     * @since 2.1
     */
    boolean isEncryptionEnabled ();


    /**
     * 
     * Property <tt>jcifs.smb.client.forceExtendedSecurity</tt> (boolean, default false)
     * 
     * @return whether to force extended security usage
     */
    boolean isForceExtendedSecurity ();


    /**
     * 
     * 
     * Property <tt>jcifs.netbios.lmhosts</tt> (string)
     * 
     * @return lmhosts file to use
     */
    String getLmHostsFileName ();


    /**
     * 
     * Property <tt>jcifs.netbios.scope</tt> (string)
     * 
     * @return default netbios scope to set in requests
     */
    String getNetbiosScope ();


    /**
     * 
     * Property <tt>jcifs.netbios.snd_buf_size</tt> (int, default 576)
     * 
     * @return netbios send buffer size
     */
    int getNetbiosSndBufSize ();


    /**
     * 
     * Property <tt>jcifs.netbios.rcv_buf_size</tt> (int, default 576)
     * 
     * @return netbios recieve buffer size
     */
    int getNetbiosRcvBufSize ();


    /**
     * 
     * Property <tt>jcifs.netbios.retryTimeout</tt> (int, default 3000)
     * 
     * @return timeout of retry requests, in milliseconds
     */
    int getNetbiosRetryTimeout ();


    /**
     * 
     * Property <tt>jcifs.netbios.retryCount</tt> (int, default 2)
     * 
     * @return maximum number of retries for netbios requests
     */
    int getNetbiosRetryCount ();


    /**
     * 
     * 
     * Property <tt>jcifs.netbios.cachePolicy</tt> in minutes (int, default 600)
     * 
     * @return netbios cache timeout, in seconds, 0 - disable caching, -1 - cache forever
     */
    int getNetbiosCachePolicy ();


    /**
     * 
     * @return the maximum size of IO buffers, limits the maximum message size
     */
    int getMaximumBufferSize ();


    /**
     * 
     * Property <tt>jcifs.smb.client.transaction_buf_size</tt> (int, default 65535)
     * 
     * @return maximum data size for SMB transactions
     */
    int getTransactionBufferSize ();


    /**
     * 
     * Property <tt>jcifs.smb.maxBuffers</tt> (int, default 16)
     * 
     * @return number of buffers to keep in cache
     */
    int getBufferCacheSize ();


    /**
     * 
     * Property <tt>jcifs.smb.client.listCount</tt> (int, default 200)
     * 
     * @return maxmimum number of elements to request in a list request
     */
    int getListCount ();


    /**
     * 
     * Property <tt>jcifs.smb.client.listSize</tt> (int, default 65535)
     * 
     * @return maximum data size for list requests
     */
    int getListSize ();


    /**
     * 
     * 
     * Property <tt>jcifs.smb.client.attrExpirationPeriod</tt> (int, 5000)
     * 
     * @return timeout of file attribute cache
     */
    long getAttributeCacheTimeout ();


    /**
     * 
     * 
     * Property <tt>jcifs.smb.client.ignoreCopyToException</tt> (boolean, false)
     * 
     * @return whether to ignore exceptions that occur during file copy
     */
    boolean isIgnoreCopyToException ();


    /**
     * @param cmd
     * @return the batch limit for the given command
     */
    int getBatchLimit ( String cmd );


    /**
     * 
     * Property <tt>jcifs.smb.client.notify_buf_size</tt> (int, default 1024)
     * 
     * @return the size of the requested server notify buffer
     */
    int getNotifyBufferSize ();


    /**
     * 
     * 
     * Property <tt>jcifs.smb.client.maxRequestRetries</tt> (int, default 2)
     * 
     * @return retry SMB requests on failure up to n times
     */
    int getMaxRequestRetries ();


    /**
     * Property <tt>jcifs.smb.client.strictResourceLifecycle</tt> (bool, default false)
     * 
     * If enabled, SmbFile instances starting with their first use will hold a reference to their tree.
     * This means that trees/sessions/connections won't be idle-disconnected even if there are no other active
     * references (currently executing code, file descriptors).
     * 
     * Depending on the usage scenario, this may have some benefit as there won't be any delays for restablishing these
     * resources, however comes at the cost of having to properly release all SmbFile instances you no longer need.
     * 
     * @return whether to use strict resource lifecycle
     */
    boolean isStrictResourceLifecycle ();


    /**
     * This is solely intended for debugging
     * 
     * @return whether to track the locations from which resources were created
     */
    boolean isTraceResourceUsage ();


    /**
     * @param command
     * @return whether to allow creating compound requests with that command
     */
    boolean isAllowCompound ( String command );


    /**
     * Machine identifier
     * 
     * ClientGuid, ... are derived from this value.
     * 
     * Normally this should be randomly assigned for each client instance/configuration.
     * 
     * @return machine identifier (32 byte)
     */
    byte[] getMachineId ();


    /**
     * 
     * 
     * Property <tt>jcifs.smb.client.disableSpnegoIntegrity</tt> (boolean, false)
     * 
     * @return whether to disable sending/verifying SPNEGO mechanismListMIC
     */
    boolean isDisableSpnegoIntegrity ();


    /**
     * 
     * Property <tt>jcifs.smb.client.enforceSpnegoIntegrity</tt> (boolean, false)
     * 
     * @return whether to enforce verifying SPNEGO mechanismListMIC
     */
    boolean isEnforceSpnegoIntegrity ();

}
