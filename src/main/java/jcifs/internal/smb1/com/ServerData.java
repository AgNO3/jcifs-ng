/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: May 13, 2017 by mbechler
 */
package jcifs.internal.smb1.com;


@SuppressWarnings ( "javadoc" )
public class ServerData {

    public byte sflags;
    public int sflags2;
    public int smaxMpxCount;
    public int maxBufferSize;
    public int sessKey;
    public int scapabilities;
    public String oemDomainName;
    public int securityMode;
    public int security;
    public boolean encryptedPasswords;
    public boolean signaturesEnabled;
    public boolean signaturesRequired;
    public int maxNumberVcs;
    public int maxRawSize;
    public long serverTime;
    public int serverTimeZone;
    public int encryptionKeyLength;
    public byte[] encryptionKey;
    public byte[] guid;
}