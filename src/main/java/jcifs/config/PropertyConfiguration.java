/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 15.01.2016 by mbechler
 */
package jcifs.config;


import java.net.InetAddress;
import java.util.Properties;

import jcifs.CIFSException;
import jcifs.Config;
import jcifs.Configuration;
import jcifs.SmbConstants;


/**
 * @author mbechler
 *
 */
public final class PropertyConfiguration extends BaseConfiguration implements Configuration {

    private final Config cfg;


    /**
     * 
     */
    public PropertyConfiguration ( Properties p ) throws CIFSException {
        this.cfg = new Config(p);

        this.useBatching = this.cfg.getBoolean("jcifs.smb.client.useBatching", true);
        this.useUnicode = this.cfg.getBoolean("jcifs.smb.client.useUnicode", true);
        this.forceUnicode = this.cfg.getBoolean("jcifs.smb.client.useUnicode", true);
        this.signingPreferred = this.cfg.getBoolean("jcifs.smb.client.signingPreferred", true);

        this.lanmanCompatibility = this.cfg.getInt("jcifs.smb.lmCompatibility", 3);
        this.disablePlainTextPasswords = this.cfg.getBoolean("jcifs.smb.client.disablePlainTextPasswords", true);

        this.oemEncoding = this.cfg.getProperty("jcifs.encoding", SmbConstants.DEFAULT_OEM_ENCODING);

        this.useNtStatus = this.cfg.getBoolean("jcifs.smb.client.useNtStatus", true);
        this.useExtendedSecurity = this.cfg.getBoolean("jcifs.smb.client.useExtendedSecurity", true);
        this.useNTSmbs = this.cfg.getBoolean("jcifs.smb.client.useNTSmbs", true);

        this.flags2 = this.cfg.getInt("jcifs.smb.client.flags2", 0);

        this.capabilities = this.cfg.getInt("jcifs.smb.client.capabilities", 0);

        this.sessionLimit = this.cfg.getInt("jcifs.smb.client.ssnLimit", SmbConstants.DEFAULT_SSN_LIMIT);

        this.smbTcpNoDelay = this.cfg.getBoolean("jcifs.smb.client.tcpNoDelay", false);
        this.smbResponseTimeout = this.cfg.getInt("jcifs.smb.client.responseTimeout", SmbConstants.DEFAULT_RESPONSE_TIMEOUT);
        this.smbSocketTimeout = this.cfg.getInt("jcifs.smb.client.soTimeout", SmbConstants.DEFAULT_SO_TIMEOUT);
        this.smbConnectionTimeout = this.cfg.getInt("jcifs.smb.client.connTimeout", SmbConstants.DEFAULT_CONN_TIMEOUT);
        this.smbLocalAddress = this.cfg.getLocalHost();
        this.smbLocalPort = this.cfg.getInt("jcifs.smb.client.lport", 0);
        this.maxMpxCount = this.cfg.getInt("jcifs.smb.client.maxMpxCount", SmbConstants.DEFAULT_MAX_MPX_COUNT);
        this.smbSendBufferSize = this.cfg.getInt("jcifs.smb.client.snd_buf_size", SmbConstants.DEFAULT_SND_BUF_SIZE);
        this.smbRecvBufferSize = this.cfg.getInt("jcifs.smb.client.rcv_buf_size", SmbConstants.DEFAULT_RCV_BUF_SIZE);
        this.smbNotifyBufferSize = this.cfg.getInt("jcifs.smb.client.notify_buf_size", SmbConstants.DEFAULT_NOTIFY_BUF_SIZE);

        this.nativeOs = this.cfg.getProperty("jcifs.smb.client.nativeOs", System.getProperty("os.name"));
        this.nativeLanMan = this.cfg.getProperty("jcifs.smb.client.nativeLanMan", "jCIFS");
        this.vcNumber = 1;

        this.dfsDisabled = this.cfg.getBoolean("jcifs.smb.client.dfs.disabled", false);
        this.dfsTTL = this.cfg.getLong("jcifs.smb.client.dfs.ttl", 300);
        this.dfsStrictView = this.cfg.getBoolean("jcifs.smb.client.dfs.strictView", false);

        this.logonShare = this.cfg.getProperty("jcifs.smb.client.logonShare", null);

        this.defaultDomain = this.cfg.getProperty("jcifs.smb.client.domain", null);
        this.defaultUserName = this.cfg.getProperty("jcifs.smb.client.username", null);
        this.defaultPassword = this.cfg.getProperty("jcifs.smb.client.password", null);

        this.netbiosHostname = this.cfg.getProperty("jcifs.netbios.hostname", null);

        this.netbiosLookupResponseLimit = this.cfg.getInt("jcifs.netbios.lookupRespLimit", 3);
        this.netbiosCachePolicy = this.cfg.getInt("jcifs.netbios.cachePolicy", 60 * 10) * 60; /* 10 hours */

        this.netbiosSocketTimeout = this.cfg.getInt("jcifs.netbios.soTimeout", 5000);
        this.netbiosSendBufferSize = this.cfg.getInt("jcifs.netbios.snd_buf_size", 576);
        this.netbiosRevcBufferSize = this.cfg.getInt("jcifs.netbios.rcv_buf_size", 576);
        this.netbiosRetryCount = this.cfg.getInt("jcifs.netbios.retryCount", 2);
        this.netbiosRetryTimeout = this.cfg.getInt("jcifs.netbios.retryTimeout", 3000);

        this.netbiosScope = this.cfg.getProperty("jcifs.netbios.scope");
        this.netbiosLocalPort = this.cfg.getInt("jcifs.netbios.lport", 0);
        this.netbiosLocalAddress = this.cfg.getInetAddress("jcifs.netbios.laddr", null);

        this.lmhostsFilename = this.cfg.getProperty("jcifs.netbios.lmhosts");
        this.winsServer = this.cfg.getInetAddressArray("jcifs.netbios.wins", ",", new InetAddress[0]);

        this.transactionBufferSize = this.cfg.getInt("jcifs.smb.client.transaction_buf_size", 0xFFFF) - 512;
        this.bufferCacheSize = this.cfg.getInt("jcifs.smb.maxBuffers", 16);

        this.smbListSize = this.cfg.getInt("jcifs.smb.client.listSize", 65535);
        this.smbListCount = this.cfg.getInt("jcifs.smb.client.listCount", 200);

        this.smbAttributeExpiration = this.cfg.getLong("jcifs.smb.client.attrExpirationPeriod", 5000L);
        this.ignoreCopyToException = this.cfg.getBoolean("jcifs.smb.client.ignoreCopyToException", true);
        this.broadcastAddress = this.cfg.getInetAddress("jcifs.netbios.baddr", null);

        initResolverOrder(this.cfg.getProperty("jcifs.resolveOrder"));
        initDefaults();
    }
}
