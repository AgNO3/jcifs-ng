/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                 "Eric Glass" <jcifs at samba dot org>
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

package jcifs.ntlmssp;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.ntlmssp.av.AvFlags;
import jcifs.ntlmssp.av.AvPair;
import jcifs.ntlmssp.av.AvPairs;
import jcifs.ntlmssp.av.AvSingleHost;
import jcifs.ntlmssp.av.AvTargetName;
import jcifs.ntlmssp.av.AvTimestamp;
import jcifs.smb.NtlmUtil;
import jcifs.util.Crypto;


/**
 * Represents an NTLMSSP Type-3 message.
 */
public class Type3Message extends NtlmMessage {

    private byte[] lmResponse;
    private byte[] ntResponse;
    private String domain;
    private String user;
    private String workstation;
    private byte[] masterKey = null;
    private byte[] sessionKey = null;
    private byte[] mic = null;
    private boolean micRequired;


    /**
     * Creates a Type-3 message using default values from the current
     * environment.
     * 
     * @param tc
     *            context to use
     */
    public Type3Message ( CIFSContext tc ) {
        setFlags(getDefaultFlags(tc));
        setDomain(tc.getConfig().getDefaultDomain());
        setUser(tc.getConfig().getDefaultUsername());
        setWorkstation(tc.getNameServiceClient().getLocalHost().getHostName());
    }


    /**
     * Creates a Type-3 message in response to the given Type-2 message.
     * 
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message which this represents a response to.
     * @param targetName
     *            SPN of the target system, optional
     * @param password
     *            The password to use when constructing the response.
     * @param domain
     *            The domain in which the user has an account.
     * @param user
     *            The username for the authenticating user.
     * @param workstation
     *            The workstation from which authentication is
     *            taking place.
     * @param flags
     * @throws GeneralSecurityException
     * @throws CIFSException
     */
    public Type3Message ( CIFSContext tc, Type2Message type2, String targetName, String password, String domain, String user, String workstation,
            int flags ) throws GeneralSecurityException, CIFSException {
        setFlags(flags | getDefaultFlags(tc, type2));
        setWorkstation(workstation);
        setDomain(domain);
        setUser(user);

        if ( password == null || password.length() == 0 ) {
            setLMResponse(null);
            setNTResponse(null);
            setUser(null);
            return;
        }

        switch ( tc.getConfig().getLanManCompatibility() ) {
        case 0:
        case 1:
            if ( !getFlag(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) ) {
                setLMResponse(getLMResponse(tc, type2, password));
                setNTResponse(getNTResponse(tc, type2, password));
            }
            else {
                // NTLM2 Session Response

                byte[] clientChallenge = new byte[24];
                tc.getConfig().getRandom().nextBytes(clientChallenge);
                java.util.Arrays.fill(clientChallenge, 8, 24, (byte) 0x00);

                byte[] responseKeyNT = NtlmUtil.nTOWFv1(password);
                byte[] ntlm2Response = NtlmUtil.getNTLM2Response(responseKeyNT, type2.getChallenge(), clientChallenge);

                setLMResponse(clientChallenge);
                setNTResponse(ntlm2Response);

                if ( getFlag(NTLMSSP_NEGOTIATE_SIGN) ) {
                    byte[] sessionNonce = new byte[16];
                    System.arraycopy(type2.getChallenge(), 0, sessionNonce, 0, 8);
                    System.arraycopy(clientChallenge, 0, sessionNonce, 8, 8);

                    MessageDigest md4 = Crypto.getMD4();
                    md4.update(responseKeyNT);
                    byte[] userSessionKey = md4.digest();

                    MessageDigest hmac = Crypto.getHMACT64(userSessionKey);
                    hmac.update(sessionNonce);
                    byte[] ntlm2SessionKey = hmac.digest();

                    if ( getFlag(NTLMSSP_NEGOTIATE_KEY_EXCH) ) {
                        this.masterKey = new byte[16];
                        tc.getConfig().getRandom().nextBytes(this.masterKey);

                        byte[] exchangedKey = new byte[16];
                        Cipher arcfour = Crypto.getArcfour(ntlm2SessionKey);
                        arcfour.update(this.masterKey, 0, 16, exchangedKey, 0);
                        setEncryptedSessionKey(exchangedKey);
                    }
                    else {
                        this.masterKey = ntlm2SessionKey;
                    }
                }
            }
            break;
        case 2:
            byte[] nt = getNTResponse(tc, type2, password);
            setLMResponse(nt);
            setNTResponse(nt);
            break;
        case 3:
        case 4:
        case 5:
            byte[] ntlmClientChallengeInfo = type2.getTargetInformation();
            List<AvPair> avPairs = ntlmClientChallengeInfo != null ? AvPairs.decode(ntlmClientChallengeInfo) : null;

            // if targetInfo has an MsvAvTimestamp
            // client should not send LmChallengeResponse
            boolean haveTimestamp = AvPairs.contains(avPairs, AvPair.MsvAvTimestamp);
            if ( !haveTimestamp ) {
                byte[] lmClientChallenge = new byte[8];
                tc.getConfig().getRandom().nextBytes(lmClientChallenge);
                setLMResponse(getLMv2Response(tc, type2, domain, user, password, lmClientChallenge));
            }
            else {
                setLMResponse(new byte[24]);
            }

            if ( avPairs != null ) {
                // make sure to set the TARGET_INFO flag as we are sending
                setFlag(NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO, true);
            }

            byte[] responseKeyNT = NtlmUtil.nTOWFv2(domain, user, password);
            byte[] ntlmClientChallenge = new byte[8];
            tc.getConfig().getRandom().nextBytes(ntlmClientChallenge);

            long ts = ( System.currentTimeMillis() + SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601 ) * 10000;
            if ( haveTimestamp ) {
                ts = ( (AvTimestamp) AvPairs.get(avPairs, AvPair.MsvAvTimestamp) ).getTimestamp();
            }

            setNTResponse(
                getNTLMv2Response(tc, type2, responseKeyNT, ntlmClientChallenge, makeAvPairs(tc, targetName, avPairs, haveTimestamp, ts), ts));

            if ( getFlag(NTLMSSP_NEGOTIATE_SIGN) ) {
                MessageDigest hmac = Crypto.getHMACT64(responseKeyNT);
                hmac.update(this.ntResponse, 0, 16); // only first 16 bytes of ntResponse
                byte[] userSessionKey = hmac.digest();

                if ( getFlag(NTLMSSP_NEGOTIATE_KEY_EXCH) ) {
                    this.masterKey = new byte[16];
                    tc.getConfig().getRandom().nextBytes(this.masterKey);

                    byte[] encryptedKey = new byte[16];
                    Cipher rc4 = Crypto.getArcfour(userSessionKey);
                    rc4.update(this.masterKey, 0, 16, encryptedKey, 0);
                    setEncryptedSessionKey(encryptedKey);
                }
                else {
                    this.masterKey = userSessionKey;
                }
            }

            break;
        default:
            setLMResponse(getLMResponse(tc, type2, password));
            setNTResponse(getNTResponse(tc, type2, password));
        }

    }


    private byte[] makeAvPairs ( CIFSContext tc, String targetName, List<AvPair> serverAvPairs, boolean haveServerTimestamp, long ts ) {
        if ( !tc.getConfig().isEnforceSpnegoIntegrity() && serverAvPairs == null ) {
            return null;
        }
        else if ( serverAvPairs == null ) {
            serverAvPairs = new LinkedList<>();
        }

        if ( getFlag(NTLMSSP_NEGOTIATE_SIGN)
                && ( tc.getConfig().isEnforceSpnegoIntegrity() || ( haveServerTimestamp && !tc.getConfig().isDisableSpnegoIntegrity() ) ) ) {
            // should provide MIC
            this.micRequired = true;
            this.mic = new byte[16];
            int curFlags = 0;
            AvFlags cur = (AvFlags) AvPairs.get(serverAvPairs, AvPair.MsvAvFlags);
            if ( cur != null ) {
                curFlags = cur.getFlags();
            }
            curFlags |= 0x2; // MAC present
            AvPairs.replace(serverAvPairs, new AvFlags(curFlags));
        }

        AvPairs.replace(serverAvPairs, new AvTimestamp(ts));

        if ( targetName != null ) {
            AvPairs.replace(serverAvPairs, new AvTargetName(targetName));
        }

        // possibly add channel bindings
        AvPairs.replace(serverAvPairs, new AvPair(0xa, new byte[16]));
        AvPairs.replace(serverAvPairs, new AvSingleHost(tc.getConfig()));

        return AvPairs.encode(serverAvPairs);
    }


    /**
     * Sets the MIC
     * 
     * @param type1
     * @param type2
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void setupMIC ( byte[] type1, byte[] type2 ) throws GeneralSecurityException, IOException {
        byte[] sk = this.masterKey;
        if ( sk == null ) {
            return;
        }
        MessageDigest mac = Crypto.getHMACT64(sk);
        mac.update(type1);
        mac.update(type2);
        byte[] type3 = toByteArray();
        mac.update(type3);
        setMic(mac.digest());
    }


    /**
     * Creates a Type-3 message with the specified parameters.
     *
     * @param flags
     *            The flags to apply to this message.
     * @param lmResponse
     *            The LanManager/LMv2 response.
     * @param ntResponse
     *            The NT/NTLMv2 response.
     * @param domain
     *            The domain in which the user has an account.
     * @param user
     *            The username for the authenticating user.
     * @param workstation
     *            The workstation from which authentication is
     *            taking place.
     */
    public Type3Message ( int flags, byte[] lmResponse, byte[] ntResponse, String domain, String user, String workstation ) {
        setFlags(flags);
        setLMResponse(lmResponse);
        setNTResponse(ntResponse);
        setDomain(domain);
        setUser(user);
        setWorkstation(workstation);
    }


    /**
     * Creates a Type-3 message using the given raw Type-3 material.
     *
     * @param material
     *            The raw Type-3 material used to construct this message.
     * @throws IOException
     *             If an error occurs while parsing the material.
     */
    public Type3Message ( byte[] material ) throws IOException {
        parse(material);
    }


    /**
     * Returns the default flags for a generic Type-3 message in the
     * current environment.
     * 
     * @param tc
     *            context to use
     * @return An <code>int</code> containing the default flags.
     */
    public static int getDefaultFlags ( CIFSContext tc ) {
        return NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_VERSION
                | ( tc.getConfig().isUseUnicode() ? NTLMSSP_NEGOTIATE_UNICODE : NTLMSSP_NEGOTIATE_OEM );
    }


    /**
     * Returns the default flags for a Type-3 message created in response
     * to the given Type-2 message in the current environment.
     * 
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message.
     * @return An <code>int</code> containing the default flags.
     */
    public static int getDefaultFlags ( CIFSContext tc, Type2Message type2 ) {
        if ( type2 == null )
            return getDefaultFlags(tc);
        int flags = NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_VERSION;
        flags |= type2.getFlag(NTLMSSP_NEGOTIATE_UNICODE) ? NTLMSSP_NEGOTIATE_UNICODE : NTLMSSP_NEGOTIATE_OEM;
        return flags;
    }


    /**
     * Returns the LanManager/LMv2 response.
     *
     * @return A <code>byte[]</code> containing the LanManager response.
     */
    public byte[] getLMResponse () {
        return this.lmResponse;
    }


    /**
     * Sets the LanManager/LMv2 response for this message.
     *
     * @param lmResponse
     *            The LanManager response.
     */
    public void setLMResponse ( byte[] lmResponse ) {
        this.lmResponse = lmResponse;
    }


    /**
     * Returns the NT/NTLMv2 response.
     *
     * @return A <code>byte[]</code> containing the NT/NTLMv2 response.
     */
    public byte[] getNTResponse () {
        return this.ntResponse;
    }


    /**
     * Sets the NT/NTLMv2 response for this message.
     *
     * @param ntResponse
     *            The NT/NTLMv2 response.
     */
    public void setNTResponse ( byte[] ntResponse ) {
        this.ntResponse = ntResponse;
    }


    /**
     * Returns the domain in which the user has an account.
     *
     * @return A <code>String</code> containing the domain for the user.
     */
    public String getDomain () {
        return this.domain;
    }


    /**
     * Sets the domain for this message.
     *
     * @param domain
     *            The domain.
     */
    public void setDomain ( String domain ) {
        this.domain = domain;
    }


    /**
     * Returns the username for the authenticating user.
     *
     * @return A <code>String</code> containing the user for this message.
     */
    public String getUser () {
        return this.user;
    }


    /**
     * Sets the user for this message.
     *
     * @param user
     *            The user.
     */
    public void setUser ( String user ) {
        this.user = user;
    }


    /**
     * Returns the workstation from which authentication is being performed.
     *
     * @return A <code>String</code> containing the workstation.
     */
    public String getWorkstation () {
        return this.workstation;
    }


    /**
     * Sets the workstation for this message.
     *
     * @param workstation
     *            The workstation.
     */
    public void setWorkstation ( String workstation ) {
        this.workstation = workstation;
    }


    /**
     * The real session key if the regular session key is actually
     * the encrypted version used for key exchange.
     *
     * @return A <code>byte[]</code> containing the session key.
     */
    public byte[] getMasterKey () {
        return this.masterKey;
    }


    /**
     * Returns the session key.
     * 
     * This is the encrypted session key included in the message,
     * if the actual session key is desired use {@link #getMasterKey()} instead.
     *
     * @return A <code>byte[]</code> containing the encrypted session key.
     */
    public byte[] getEncryptedSessionKey () {
        return this.sessionKey;
    }


    /**
     * Sets the session key.
     *
     * @param sessionKey
     *            The session key.
     */
    public void setEncryptedSessionKey ( byte[] sessionKey ) {
        this.sessionKey = sessionKey;
    }


    /**
     * @return A <code>byte[]</code> containing the message integrity code.
     */
    public byte[] getMic () {
        return this.mic;
    }


    /**
     * @param mic
     *            NTLM mic to set (16 bytes)
     */
    public void setMic ( byte[] mic ) {
        this.mic = mic;
    }


    /**
     * @return whether a MIC should be calulated
     */
    public boolean isMICRequired () {
        return this.micRequired;
    }


    @Override
    public byte[] toByteArray () throws IOException {
        int size = 64;
        boolean unicode = getFlag(NTLMSSP_NEGOTIATE_UNICODE);
        String oemCp = unicode ? null : getOEMEncoding();

        String domainName = getDomain();
        byte[] domainBytes = null;
        if ( domainName != null && domainName.length() != 0 ) {
            domainBytes = unicode ? domainName.getBytes(UNI_ENCODING) : domainName.getBytes(oemCp);
            size += domainBytes.length;
        }

        String userName = getUser();
        byte[] userBytes = null;
        if ( userName != null && userName.length() != 0 ) {
            userBytes = unicode ? userName.getBytes(UNI_ENCODING) : userName.toUpperCase().getBytes(oemCp);
            size += userBytes.length;
        }

        String workstationName = getWorkstation();
        byte[] workstationBytes = null;
        if ( workstationName != null && workstationName.length() != 0 ) {
            workstationBytes = unicode ? workstationName.getBytes(UNI_ENCODING) : workstationName.toUpperCase().getBytes(oemCp);
            size += workstationBytes.length;
        }

        byte[] micBytes = getMic();
        if ( micBytes != null ) {
            size += 8 + 16;
        }
        else if ( getFlag(NTLMSSP_NEGOTIATE_VERSION) ) {
            size += 8;
        }

        byte[] lmResponseBytes = getLMResponse();
        size += ( lmResponseBytes != null ) ? lmResponseBytes.length : 0;

        byte[] ntResponseBytes = getNTResponse();
        size += ( ntResponseBytes != null ) ? ntResponseBytes.length : 0;

        byte[] sessionKeyBytes = getEncryptedSessionKey();
        size += ( sessionKeyBytes != null ) ? sessionKeyBytes.length : 0;

        byte[] type3 = new byte[size];
        int pos = 0;

        System.arraycopy(NTLMSSP_SIGNATURE, 0, type3, 0, 8);
        pos += 8;

        writeULong(type3, pos, NTLMSSP_TYPE3);
        pos += 4;

        int lmOff = writeSecurityBuffer(type3, 12, lmResponseBytes);
        pos += 8;
        int ntOff = writeSecurityBuffer(type3, 20, ntResponseBytes);
        pos += 8;
        int domOff = writeSecurityBuffer(type3, 28, domainBytes);
        pos += 8;
        int userOff = writeSecurityBuffer(type3, 36, userBytes);
        pos += 8;
        int wsOff = writeSecurityBuffer(type3, 44, workstationBytes);
        pos += 8;
        int skOff = writeSecurityBuffer(type3, 52, sessionKeyBytes);
        pos += 8;

        writeULong(type3, pos, getFlags());
        pos += 4;

        if ( getFlag(NTLMSSP_NEGOTIATE_VERSION) ) {
            System.arraycopy(NTLMSSP_VERSION, 0, type3, pos, NTLMSSP_VERSION.length);
            pos += NTLMSSP_VERSION.length;
        }
        else if ( micBytes != null ) {
            pos += NTLMSSP_VERSION.length;
        }

        if ( micBytes != null ) {
            System.arraycopy(micBytes, 0, type3, pos, 16);
            pos += 16;
        }

        pos += writeSecurityBufferContent(type3, pos, lmOff, lmResponseBytes);
        pos += writeSecurityBufferContent(type3, pos, ntOff, ntResponseBytes);
        pos += writeSecurityBufferContent(type3, pos, domOff, domainBytes);
        pos += writeSecurityBufferContent(type3, pos, userOff, userBytes);
        pos += writeSecurityBufferContent(type3, pos, wsOff, workstationBytes);
        pos += writeSecurityBufferContent(type3, pos, skOff, sessionKeyBytes);

        return type3;

    }


    @Override
    public String toString () {
        String userString = getUser();
        String domainString = getDomain();
        String workstationString = getWorkstation();
        byte[] lmResponseBytes = getLMResponse();
        byte[] ntResponseBytes = getNTResponse();
        byte[] sessionKeyBytes = getEncryptedSessionKey();

        return "Type3Message[domain=" + domainString + ",user=" + userString + ",workstation=" + workstationString + ",lmResponse="
                + ( lmResponseBytes == null ? "null" : "<" + lmResponseBytes.length + " bytes>" ) + ",ntResponse="
                + ( ntResponseBytes == null ? "null" : "<" + ntResponseBytes.length + " bytes>" ) + ",sessionKey="
                + ( sessionKeyBytes == null ? "null" : "<" + sessionKeyBytes.length + " bytes>" ) + ",flags=0x"
                + jcifs.util.Hexdump.toHexString(getFlags(), 8) + "]";
    }


    /**
     * Constructs the LanManager response to the given Type-2 message using
     * the supplied password.
     * 
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message.
     * @param password
     *            The password.
     * @return A <code>byte[]</code> containing the LanManager response.
     * @throws GeneralSecurityException
     */
    public static byte[] getLMResponse ( CIFSContext tc, Type2Message type2, String password ) throws GeneralSecurityException {
        if ( type2 == null || password == null )
            return null;
        return NtlmUtil.getPreNTLMResponse(tc, password, type2.getChallenge());
    }


    /**
     * 
     * @param tc
     * @param type2
     * @param domain
     * @param user
     * @param password
     * @param clientChallenge
     * @return the calculated response
     * @throws GeneralSecurityException
     */
    public static byte[] getLMv2Response ( CIFSContext tc, Type2Message type2, String domain, String user, String password, byte[] clientChallenge )
            throws GeneralSecurityException {
        if ( type2 == null || domain == null || user == null || password == null || clientChallenge == null ) {
            return null;
        }
        return NtlmUtil.getLMv2Response(domain, user, password, type2.getChallenge(), clientChallenge);
    }


    /**
     * 
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message.
     * @param responseKeyNT
     * @param clientChallenge
     * @param clientChallengeInfo
     * @param ts
     *            timestamp (nanos since 1601)
     * @return A <code>byte[]</code> containing the NTLMv2 response.
     */
    public static byte[] getNTLMv2Response ( CIFSContext tc, Type2Message type2, byte[] responseKeyNT, byte[] clientChallenge,
            byte[] clientChallengeInfo, long ts ) {
        if ( type2 == null || responseKeyNT == null || clientChallenge == null ) {
            return null;
        }
        return NtlmUtil.getNTLMv2Response(responseKeyNT, type2.getChallenge(), clientChallenge, ts, clientChallengeInfo);
    }


    /**
     * Constructs the NT response to the given Type-2 message using
     * the supplied password.
     * 
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message.
     * @param password
     *            The password.
     * @return A <code>byte[]</code> containing the NT response.
     * @throws GeneralSecurityException
     */
    public static byte[] getNTResponse ( CIFSContext tc, Type2Message type2, String password ) throws GeneralSecurityException {
        if ( type2 == null || password == null )
            return null;
        return NtlmUtil.getNTLMResponse(password, type2.getChallenge());
    }


    private void parse ( byte[] material ) throws IOException {
        int pos = 0;
        for ( int i = 0; i < 8; i++ ) {
            if ( material[ i ] != NTLMSSP_SIGNATURE[ i ] ) {
                throw new IOException("Not an NTLMSSP message.");
            }
        }

        pos += 8;
        if ( readULong(material, pos) != NTLMSSP_TYPE3 ) {
            throw new IOException("Not a Type 3 message.");
        }
        pos += 4;

        byte[] lmResponseBytes = readSecurityBuffer(material, pos);
        setLMResponse(lmResponseBytes);
        int lmResponseOffset = readULong(material, pos + 4);
        pos += 8;

        byte[] ntResponseBytes = readSecurityBuffer(material, pos);
        setNTResponse(ntResponseBytes);
        int ntResponseOffset = readULong(material, pos + 4);
        pos += 8;

        byte[] domainBytes = readSecurityBuffer(material, pos);
        int domainOffset = readULong(material, pos + 4);
        pos += 8;

        byte[] userBytes = readSecurityBuffer(material, pos);
        int userOffset = readULong(material, pos + 4);
        pos += 8;

        byte[] workstationBytes = readSecurityBuffer(material, pos);
        int workstationOffset = readULong(material, pos + 4);
        pos += 8;

        boolean end = false;
        int flags;
        String charset;
        if ( lmResponseOffset < pos + 12 || ntResponseOffset < pos + 12 || domainOffset < pos + 12 || userOffset < pos + 12
                || workstationOffset < pos + 12 ) {
            // no room for SK/Flags
            flags = NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM;
            setFlags(flags);
            charset = getOEMEncoding();
            end = true;
        }
        else {
            setEncryptedSessionKey(readSecurityBuffer(material, pos));
            pos += 8;

            flags = readULong(material, pos);
            setFlags(flags);
            pos += 4;

            charset = ( ( flags & NTLMSSP_NEGOTIATE_UNICODE ) != 0 ) ? UNI_ENCODING : getOEMEncoding();
        }

        setDomain(new String(domainBytes, charset));
        setUser(new String(userBytes, charset));
        setWorkstation(new String(workstationBytes, charset));

        int micLen = pos + 24; // Version + MIC
        if ( end || lmResponseOffset < micLen || ntResponseOffset < micLen || domainOffset < micLen || userOffset < micLen
                || workstationOffset < micLen ) {
            return;
        }

        pos += 8; // Version

        byte[] m = new byte[16];
        System.arraycopy(material, pos, m, 0, m.length);
        setMic(m);
    }

}
