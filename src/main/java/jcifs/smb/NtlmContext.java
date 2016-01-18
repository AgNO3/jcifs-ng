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


import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.ntlmssp.NtlmFlags;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.util.Hexdump;


/**
 * For initiating NTLM authentication (including NTLMv2). If you want to add NTLMv2 authentication support to something
 * this is what you want to use. See the code for details. Note that JCIFS does not implement the acceptor side of NTLM
 * authentication.
 */

public class NtlmContext {

    private static final Logger log = Logger.getLogger(NtlmContext.class);

    private NtlmPasswordAuthentication auth;
    private int ntlmsspFlags;
    private String workstation;
    private boolean isEstablished = false;
    private byte[] serverChallenge = null;
    private byte[] signingKey = null;
    private String netbiosName = null;
    int state = 1;

    private CIFSContext transportContext;


    public NtlmContext ( CIFSContext tc, NtlmPasswordAuthentication auth, boolean doSigning ) {
        this.transportContext = tc;
        this.auth = auth;
        this.ntlmsspFlags = this.ntlmsspFlags | NtlmFlags.NTLMSSP_REQUEST_TARGET | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM2
                | NtlmFlags.NTLMSSP_NEGOTIATE_128;
        if ( doSigning ) {
            this.ntlmsspFlags |= NtlmFlags.NTLMSSP_NEGOTIATE_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH;
        }
        this.workstation = tc.getNameServiceClient().getLocalHost().getHostName();
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
        if ( this.signingKey == null ) {
            ret += "null";
        }
        else {
            ret += Hexdump.toHexString(this.signingKey, 0, this.signingKey.length * 2);
        }
        ret += "]";
        return ret;
    }


    public boolean isEstablished () {
        return this.isEstablished;
    }


    public byte[] getServerChallenge () {
        return this.serverChallenge;
    }


    public byte[] getSigningKey () {
        return this.signingKey;
    }


    public String getNetbiosName () {
        return this.netbiosName;
    }


    public byte[] initSecContext ( byte[] token, int offset, int len ) throws SmbException {
        switch ( this.state ) {
        case 1:
            Type1Message msg1 = new Type1Message(this.transportContext, this.ntlmsspFlags, this.auth.getUserDomain(), this.workstation);
            token = msg1.toByteArray();

            if ( log.isTraceEnabled() ) {
                log.trace(msg1);
                log.trace(Hexdump.toHexString(token, 0, token.length));
            }

            this.state++;
            break;
        case 2:
            try {
                Type2Message msg2 = new Type2Message(token);

                if ( log.isTraceEnabled() ) {
                    log.trace(msg2);
                    log.trace(Hexdump.toHexString(token, 0, token.length));
                }

                this.serverChallenge = msg2.getChallenge();
                this.ntlmsspFlags &= msg2.getFlags();
                Type3Message msg3 = new Type3Message(
                    this.transportContext,
                    msg2,
                    this.auth.getPassword(),
                    this.auth.getUserDomain(),
                    this.auth.getUsername(),
                    this.workstation,
                    this.ntlmsspFlags);
                token = msg3.toByteArray();

                if ( log.isTraceEnabled() ) {
                    log.trace(msg3);
                    log.trace(Hexdump.toHexString(token, 0, token.length));
                }
                if ( ( this.ntlmsspFlags & NtlmFlags.NTLMSSP_NEGOTIATE_SIGN ) != 0 )
                    this.signingKey = msg3.getMasterKey();

                this.isEstablished = true;
                this.state++;
                break;
            }
            catch ( Exception e ) {
                throw new SmbException(e.getMessage(), e);
            }
        default:
            throw new SmbException("Invalid state");
        }
        return token;
    }
}
