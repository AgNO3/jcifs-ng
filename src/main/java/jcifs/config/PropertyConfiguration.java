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
import java.util.Properties;

import jcifs.CIFSException;
import jcifs.Config;
import jcifs.Configuration;
import jcifs.DialectVersion;
import jcifs.SmbConstants;


/**
 * Configuration implementation reading the classic jcifs settings from properties
 * 
 * @author mbechler
 *
 */
public final class PropertyConfiguration extends BaseConfiguration implements Configuration {

    /**
     * @param p
     *            read from properties
     * @throws CIFSException
     * 
     */
    public PropertyConfiguration ( Properties p ) throws CIFSException {
        this.useBatching = Config.getBoolean(p, "jcifs.smb.client.useBatching", true);
        this.useUnicode = Config.getBoolean(p, "jcifs.smb.client.useUnicode", true);
        this.useLargeReadWrite = Config.getBoolean(p, "jcifs.smb.client.useLargeReadWrite", true);
        this.forceUnicode = Config.getBoolean(p, "jcifs.smb.client.forceUnicode", false);
        this.signingPreferred = Config.getBoolean(p, "jcifs.smb.client.signingPreferred", false);
        this.signingEnforced = Config.getBoolean(p, "jcifs.smb.client.signingEnforced", false);
        this.ipcSigningEnforced = Config.getBoolean(p, "jcifs.smb.client.ipcSigningEnforced", true);
        this.encryptionEnabled = Config.getBoolean(p, "jcifs.smb.client.encryptionEnabled", false);

        this.lanmanCompatibility = Config.getInt(p, "jcifs.smb.lmCompatibility", 3);
        this.allowNTLMFallback = Config.getBoolean(p, "jcifs.smb.allowNTLMFallback", true);
        this.useRawNTLM = Config.getBoolean(p, "jcifs.smb.useRawNTLM", false);

        this.disableSpnegoIntegrity = Config.getBoolean(p, "jcifs.smb.client.disableSpnegoIntegrity", false);
        this.enforceSpnegoIntegrity = Config.getBoolean(p, "jcifs.smb.client.enforceSpnegoIntegrity", false);

        this.disablePlainTextPasswords = Config.getBoolean(p, "jcifs.smb.client.disablePlainTextPasswords", true);

        this.oemEncoding = p.getProperty("jcifs.encoding", SmbConstants.DEFAULT_OEM_ENCODING);

        this.useNtStatus = Config.getBoolean(p, "jcifs.smb.client.useNtStatus", true);
        this.useExtendedSecurity = Config.getBoolean(p, "jcifs.smb.client.useExtendedSecurity", true);
        this.forceExtendedSecurity = Config.getBoolean(p, "jcifs.smb.client.forceExtendedSecurity", false);

        this.smb2OnlyNegotiation = Config.getBoolean(p, "jcifs.smb.client.useSMB2Negotiation", false);
        this.port139FailoverEnabled = Config.getBoolean(p, "jcifs.smb.client.port139.enabled", false);

        this.useNTSmbs = Config.getBoolean(p, "jcifs.smb.client.useNTSmbs", true);

        this.flags2 = Config.getInt(p, "jcifs.smb.client.flags2", 0);

        this.capabilities = Config.getInt(p, "jcifs.smb.client.capabilities", 0);

        this.sessionLimit = Config.getInt(p, "jcifs.smb.client.ssnLimit", SmbConstants.DEFAULT_SSN_LIMIT);

        this.maxRequestRetries = Config.getInt(p, "jcifs.smb.client.maxRequestRetries", 2);

        this.smbTcpNoDelay = Config.getBoolean(p, "jcifs.smb.client.tcpNoDelay", false);
        this.smbResponseTimeout = Config.getInt(p, "jcifs.smb.client.responseTimeout", SmbConstants.DEFAULT_RESPONSE_TIMEOUT);
        this.smbSocketTimeout = Config.getInt(p, "jcifs.smb.client.soTimeout", SmbConstants.DEFAULT_SO_TIMEOUT);
        this.smbConnectionTimeout = Config.getInt(p, "jcifs.smb.client.connTimeout", SmbConstants.DEFAULT_CONN_TIMEOUT);
        this.smbSessionTimeout = Config.getInt(p, "jcifs.smb.client.sessionTimeout", SmbConstants.DEFAULT_CONN_TIMEOUT);
        this.idleTimeoutDisabled = Config.getBoolean(p, "jcifs.smb.client.disableIdleTimeout", false);

        this.smbLocalAddress = Config.getLocalHost(p);
        this.smbLocalPort = Config.getInt(p, "jcifs.smb.client.lport", 0);
        this.maxMpxCount = Config.getInt(p, "jcifs.smb.client.maxMpxCount", SmbConstants.DEFAULT_MAX_MPX_COUNT);
        this.smbSendBufferSize = Config.getInt(p, "jcifs.smb.client.snd_buf_size", SmbConstants.DEFAULT_SND_BUF_SIZE);
        this.smbRecvBufferSize = Config.getInt(p, "jcifs.smb.client.rcv_buf_size", SmbConstants.DEFAULT_RCV_BUF_SIZE);
        this.smbNotifyBufferSize = Config.getInt(p, "jcifs.smb.client.notify_buf_size", SmbConstants.DEFAULT_NOTIFY_BUF_SIZE);

        this.nativeOs = p.getProperty("jcifs.smb.client.nativeOs", System.getProperty("os.name"));
        this.nativeLanMan = p.getProperty("jcifs.smb.client.nativeLanMan", "jCIFS");
        this.vcNumber = 1;

        this.dfsDisabled = Config.getBoolean(p, "jcifs.smb.client.dfs.disabled", false);
        this.dfsTTL = Config.getLong(p, "jcifs.smb.client.dfs.ttl", 300);
        this.dfsStrictView = Config.getBoolean(p, "jcifs.smb.client.dfs.strictView", false);
        this.dfsConvertToFqdn = Config.getBoolean(p, "jcifs.smb.client.dfs.convertToFQDN", false);

        this.logonShare = p.getProperty("jcifs.smb.client.logonShare", null);

        this.defaultDomain = p.getProperty("jcifs.smb.client.domain", null);
        this.defaultUserName = p.getProperty("jcifs.smb.client.username", null);
        this.defaultPassword = p.getProperty("jcifs.smb.client.password", null);

        this.netbiosHostname = p.getProperty("jcifs.netbios.hostname", null);

        this.netbiosCachePolicy = Config.getInt(p, "jcifs.netbios.cachePolicy", 60 * 10) * 60; /* 10 hours */

        this.netbiosSocketTimeout = Config.getInt(p, "jcifs.netbios.soTimeout", 5000);
        this.netbiosSendBufferSize = Config.getInt(p, "jcifs.netbios.snd_buf_size", 576);
        this.netbiosRevcBufferSize = Config.getInt(p, "jcifs.netbios.rcv_buf_size", 576);
        this.netbiosRetryCount = Config.getInt(p, "jcifs.netbios.retryCount", 2);
        this.netbiosRetryTimeout = Config.getInt(p, "jcifs.netbios.retryTimeout", 3000);

        this.netbiosScope = p.getProperty("jcifs.netbios.scope");
        this.netbiosLocalPort = Config.getInt(p, "jcifs.netbios.lport", 0);
        this.netbiosLocalAddress = Config.getInetAddress(p, "jcifs.netbios.laddr", null);

        this.lmhostsFilename = p.getProperty("jcifs.netbios.lmhosts");
        this.winsServer = Config.getInetAddressArray(p, "jcifs.netbios.wins", ",", new InetAddress[0]);

        this.transactionBufferSize = Config.getInt(p, "jcifs.smb.client.transaction_buf_size", 0xFFFF) - 512;
        this.bufferCacheSize = Config.getInt(p, "jcifs.smb.maxBuffers", 16);

        this.smbListSize = Config.getInt(p, "jcifs.smb.client.listSize", 65535);
        this.smbListCount = Config.getInt(p, "jcifs.smb.client.listCount", 200);

        this.smbAttributeExpiration = Config.getLong(p, "jcifs.smb.client.attrExpirationPeriod", 5000L);
        this.ignoreCopyToException = Config.getBoolean(p, "jcifs.smb.client.ignoreCopyToException", false);
        this.broadcastAddress = Config.getInetAddress(p, "jcifs.netbios.baddr", null);

        this.traceResourceUsage = Config.getBoolean(p, "jcifs.traceResources", false);
        this.strictResourceLifecycle = Config.getBoolean(p, "jcifs.smb.client.strictResourceLifecycle", false);

        String minVer = p.getProperty("jcifs.smb.client.minVersion");
        String maxVer = p.getProperty("jcifs.smb.client.maxVersion");

        if ( minVer != null || maxVer != null ) {
            initProtocolVersions(minVer, maxVer);
        }
        else {
            boolean smb2 = Config.getBoolean(p, "jcifs.smb.client.enableSMB2", true);
            boolean nosmb1 = Config.getBoolean(p, "jcifs.smb.client.disableSMB1", false);
            initProtocolVersions(nosmb1 ? DialectVersion.SMB202 : null, !smb2 ? DialectVersion.SMB1 : null);
        }

        initResolverOrder(p.getProperty("jcifs.resolveOrder"));
        initDisallowCompound(p.getProperty("jcifs.smb.client.disallowCompound"));
        initDefaults();
    }

}
