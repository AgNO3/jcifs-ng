/* jcifs smb client library in Java
 * Copyright (C) 2008  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.smb;


import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.internal.util.SMBUtil;
import jcifs.ntlmssp.NtlmFlags;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.util.Crypto;
import jcifs.util.Hexdump;


/**
 * For initiating NTLM authentication (including NTLMv2). If you want to add NTLMv2 authentication support to something
 * this is what you want to use. See the code for details. Note that JCIFS does not implement the acceptor side of NTLM
 * authentication.
 * 
 */
public class NtlmContext implements SSPContext {

    private static final String S2C_SIGN_CONSTANT = "session key to server-to-client signing key magic constant";
    private static final String S2C_SEAL_CONSTANT = "session key to server-to-client sealing key magic constant";

    private static final String C2S_SIGN_CONSTANT = "session key to client-to-server signing key magic constant";
    private static final String C2S_SEAL_CONSTANT = "session key to client-to-server sealing key magic constant";

    private static final Logger log = LoggerFactory.getLogger(NtlmContext.class);

    /**
     * 
     */
    public static ASN1ObjectIdentifier NTLMSSP_OID;

    static {
        try {
            NTLMSSP_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10");
        }
        catch ( IllegalArgumentException e ) {
            log.error("Failed to parse OID", e);
        }
    }

    private NtlmPasswordAuthenticator auth;
    private int ntlmsspFlags;
    private String workstation;
    private boolean isEstablished = false;
    private byte[] serverChallenge = null;
    private byte[] masterKey = null;
    private String netbiosName = null;

    private final boolean requireKeyExchange;
    private final AtomicInteger signSequence = new AtomicInteger(0);
    private final AtomicInteger verifySequence = new AtomicInteger(0);
    private int state = 1;

    private CIFSContext transportContext;

    private String targetName;
    private byte[] type1Bytes;

    private byte[] signKey;
    private byte[] verifyKey;
    private byte[] sealClientKey;
    private byte[] sealServerKey;

    private Cipher sealClientHandle;
    private Cipher sealServerHandle;


    /**
     * @param tc
     *            context to use
     * @param auth
     *            credentials
     * @param doSigning
     *            whether signing is requested
     */
    public NtlmContext ( CIFSContext tc, NtlmPasswordAuthenticator auth, boolean doSigning ) {
        this.transportContext = tc;
        this.auth = auth;
        this.ntlmsspFlags = this.ntlmsspFlags | NtlmFlags.NTLMSSP_REQUEST_TARGET | NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                | NtlmFlags.NTLMSSP_NEGOTIATE_128;
        if ( !auth.isAnonymous() ) {
            this.ntlmsspFlags |= NtlmFlags.NTLMSSP_NEGOTIATE_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH;
        }
        else {
            this.ntlmsspFlags |= NtlmFlags.NTLMSSP_NEGOTIATE_ANONYMOUS;
        }
        this.requireKeyExchange = doSigning;
        this.workstation = tc.getConfig().getNetbiosHostname();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#getSupportedMechs()
     */
    @Override
    public ASN1ObjectIdentifier[] getSupportedMechs () {
        return new ASN1ObjectIdentifier[] {
            NTLMSSP_OID
        };
    }


    @Override
    public String toString () {
        String ret = "NtlmContext[auth=" + this.auth + ",ntlmsspFlags=0x" + Hexdump.toHexString(this.ntlmsspFlags, 8) + ",workstation="
                + this.workstation + ",isEstablished=" + this.isEstablished + ",state=" + this.state + ",serverChallenge=";
        if ( this.serverChallenge == null ) {
            ret += "null";
        }
        else {
            ret += Hexdump.toHexString(this.serverChallenge, 0, this.serverChallenge.length * 2);
        }
        ret += ",signingKey=";
        if ( this.masterKey == null ) {
            ret += "null";
        }
        else {
            ret += Hexdump.toHexString(this.masterKey, 0, this.masterKey.length * 2);
        }
        ret += "]";
        return ret;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#getFlags()
     */
    @Override
    public int getFlags () {
        return 0;
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#isSupported(org.bouncycastle.asn1.ASN1ObjectIdentifier)
     */
    @Override
    public boolean isSupported ( ASN1ObjectIdentifier mechanism ) {
        return NTLMSSP_OID.equals(mechanism);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#isPreferredMech(org.bouncycastle.asn1.ASN1ObjectIdentifier)
     */
    @Override
    public boolean isPreferredMech ( ASN1ObjectIdentifier mechanism ) {
        return this.auth.isPreferredMech(mechanism);
    }


    @Override
    public boolean isEstablished () {
        return this.isEstablished;
    }


    /**
     * @return the server's challenge
     */
    public byte[] getServerChallenge () {
        return this.serverChallenge;
    }


    @Override
    public byte[] getSigningKey () {
        return this.masterKey;
    }


    @Override
    public String getNetbiosName () {
        return this.netbiosName;
    }


    /**
     * @param targetName
     *            the target's SPN
     */
    public void setTargetName ( String targetName ) {
        this.targetName = targetName;
    }


    @Override
    public byte[] initSecContext ( byte[] token, int offset, int len ) throws SmbException {
        switch ( this.state ) {
        case 1:
            return makeNegotiate(token);
        case 2:
            return makeAuthenticate(token);
        default:
            throw new SmbException("Invalid state");
        }
    }


    protected byte[] makeAuthenticate ( byte[] token ) throws SmbException {
        try {
            Type2Message msg2 = new Type2Message(token);

            if ( log.isTraceEnabled() ) {
                log.trace(msg2.toString());
                log.trace(Hexdump.toHexString(token, 0, token.length));
            }

            this.serverChallenge = msg2.getChallenge();

            if ( this.requireKeyExchange ) {
                if ( !this.transportContext.getConfig().isEnforceSpnegoIntegrity() && ( !msg2.getFlag(NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH)
                        || !msg2.getFlag(NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) ) ) {
                    throw new SmbUnsupportedOperationException("Server does not support extended NTLMv2 key exchange");
                }

                if ( !msg2.getFlag(NtlmFlags.NTLMSSP_NEGOTIATE_SIGN) ) {
                    throw new SmbUnsupportedOperationException("Server does not support basic NTLM signature key exchange");
                }
                else if ( !msg2.getFlag(NtlmFlags.NTLMSSP_NEGOTIATE_128) ) {
                    throw new SmbUnsupportedOperationException("Server does not support 128-bit keys");
                }
            }

            this.ntlmsspFlags &= msg2.getFlags();

            Type3Message msg3 = new Type3Message(
                this.transportContext,
                msg2,
                this.targetName,
                this.auth.getPassword(),
                this.auth.getUserDomain(),
                this.auth.getUsername(),
                this.workstation,
                this.ntlmsspFlags);

            msg3.setupMIC(this.type1Bytes, token);

            byte[] out = msg3.toByteArray();

            if ( log.isTraceEnabled() ) {
                log.trace(msg3.toString());
                log.trace(Hexdump.toHexString(token, 0, token.length));
            }
            if ( ( this.ntlmsspFlags & NtlmFlags.NTLMSSP_NEGOTIATE_SIGN ) != 0 ) {
                this.masterKey = msg3.getMasterKey();

                if ( ( this.ntlmsspFlags & NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY ) != 0 ) {
                    initSessionSecurity(msg3.getMasterKey());
                }
            }

            this.isEstablished = true;
            this.state++;
            return out;
        }
        catch ( SmbException e ) {
            throw e;
        }
        catch ( Exception e ) {
            throw new SmbException(e.getMessage(), e);
        }
    }


    protected byte[] makeNegotiate ( byte[] token ) {
        Type1Message msg1 = new Type1Message(this.transportContext, this.ntlmsspFlags, this.auth.getUserDomain(), this.workstation);
        byte[] out = msg1.toByteArray();
        this.type1Bytes = out;

        if ( log.isTraceEnabled() ) {
            log.trace(msg1.toString());
            log.trace(Hexdump.toHexString(out, 0, out.length));
        }

        this.state++;
        return out;
    }


    protected void initSessionSecurity ( byte[] mk ) {
        this.signKey = deriveKey(mk, C2S_SIGN_CONSTANT);
        this.verifyKey = deriveKey(mk, S2C_SIGN_CONSTANT);

        if ( log.isDebugEnabled() ) {
            log.debug("Sign key is " + Hexdump.toHexString(this.signKey));
            log.debug("Verify key is " + Hexdump.toHexString(this.verifyKey));
        }

        this.sealClientKey = deriveKey(mk, C2S_SEAL_CONSTANT);
        this.sealClientHandle = Crypto.getArcfour(this.sealClientKey);
        if ( log.isDebugEnabled() ) {
            log.debug("Seal key is " + Hexdump.toHexString(this.sealClientKey));
        }

        this.sealServerKey = deriveKey(mk, S2C_SEAL_CONSTANT);
        this.sealServerHandle = Crypto.getArcfour(this.sealServerKey);

        if ( log.isDebugEnabled() ) {
            log.debug("Server seal key is " + Hexdump.toHexString(this.sealServerKey));
        }
    }


    private static byte[] deriveKey ( byte[] masterKey, String cnst ) {
        MessageDigest md5 = Crypto.getMD5();
        md5.update(masterKey);
        md5.update(cnst.getBytes(StandardCharsets.US_ASCII));
        md5.update((byte) 0);
        return md5.digest();
    }


    @Override
    public boolean supportsIntegrity () {
        return true;
    }


    @Override
    public boolean isMICAvailable () {
        return this.signKey != null && this.verifyKey != null;
    }


    @Override
    public byte[] calculateMIC ( byte[] data ) throws CIFSException {
        byte[] sk = this.signKey;
        if ( sk == null ) {
            throw new CIFSException("Signing is not initialized");
        }

        int seqNum = this.signSequence.getAndIncrement();
        byte[] seqBytes = new byte[4];
        SMBUtil.writeInt4(seqNum, seqBytes, 0);

        MessageDigest mac = Crypto.getHMACT64(sk);
        mac.update(seqBytes); // sequence
        mac.update(data); // data
        byte[] dgst = mac.digest();
        byte[] trunc = new byte[8];
        System.arraycopy(dgst, 0, trunc, 0, 8);

        if ( log.isDebugEnabled() ) {
            log.debug("Digest " + Hexdump.toHexString(dgst));
            log.debug("Truncated " + Hexdump.toHexString(trunc));
        }

        if ( ( this.ntlmsspFlags & NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH ) != 0 ) {
            try {
                trunc = this.sealClientHandle.doFinal(trunc);
                if ( log.isDebugEnabled() ) {
                    log.debug("Encrypted " + Hexdump.toHexString(trunc));
                }
            }
            catch ( GeneralSecurityException e ) {
                throw new CIFSException("Failed to encrypt MIC", e);
            }
        }

        byte[] sig = new byte[16];
        SMBUtil.writeInt4(1, sig, 0); // version
        System.arraycopy(trunc, 0, sig, 4, 8); // checksum
        SMBUtil.writeInt4(seqNum, sig, 12); // seqNum

        return sig;
    }


    @Override
    public void verifyMIC ( byte[] data, byte[] mic ) throws CIFSException {
        byte[] sk = this.verifyKey;
        if ( sk == null ) {
            throw new CIFSException("Signing is not initialized");
        }

        int ver = SMBUtil.readInt4(mic, 0);
        if ( ver != 1 ) {
            throw new SmbUnsupportedOperationException("Invalid signature version");
        }

        MessageDigest mac = Crypto.getHMACT64(sk);
        int seq = SMBUtil.readInt4(mic, 12);
        mac.update(mic, 12, 4); // sequence
        byte[] dgst = mac.digest(data); // data
        byte[] trunc = Arrays.copyOf(dgst, 8);

        if ( log.isDebugEnabled() ) {
            log.debug("Digest " + Hexdump.toHexString(dgst));
            log.debug("Truncated " + Hexdump.toHexString(trunc));
        }

        boolean encrypted = ( this.ntlmsspFlags & NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH ) != 0;
        if ( encrypted ) {
            try {
                trunc = this.sealServerHandle.doFinal(trunc);
                if ( log.isDebugEnabled() ) {
                    log.debug("Decrypted " + Hexdump.toHexString(trunc));
                }
            }
            catch ( GeneralSecurityException e ) {
                throw new CIFSException("Failed to decrypt MIC", e);
            }
        }

        int expectSeq = this.verifySequence.getAndIncrement();
        if ( expectSeq != seq ) {
            throw new CIFSException(String.format("Invalid MIC sequence, expect %d have %d", expectSeq, seq));
        }

        byte[] verify = new byte[8];
        System.arraycopy(mic, 4, verify, 0, 8);
        if ( !MessageDigest.isEqual(trunc, verify) ) {
            if ( log.isDebugEnabled() ) {
                log.debug(String.format("Seq = %d ver = %d encrypted = %s", seq, ver, encrypted));
                log.debug(String.format("Expected MIC %s != %s", Hexdump.toHexString(trunc), Hexdump.toHexString(verify)));
            }
            throw new CIFSException("Invalid MIC");
        }

    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.SSPContext#dispose()
     */
    @Override
    public void dispose () throws SmbException {
        this.isEstablished = false;
        this.sealClientHandle = null;
        this.sealServerHandle = null;
        this.sealClientKey = null;
        this.sealServerKey = null;
        this.masterKey = null;
        this.signKey = null;
        this.verifyKey = null;
        this.type1Bytes = null;
    }
}
