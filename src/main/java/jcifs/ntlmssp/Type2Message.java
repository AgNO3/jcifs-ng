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
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;


/**
 * Represents an NTLMSSP Type-2 message.
 */
public class Type2Message extends NtlmMessage {

    private static final Logger log = LoggerFactory.getLogger(Type2Message.class);

    private byte[] challenge;
    private String target;
    private byte[] context;
    private byte[] targetInformation;

    private static final Map<String, byte[]> TARGET_INFO_CACHE = new HashMap<>();


    private static byte[] getDefaultTargetInfo ( CIFSContext tc ) {
        String domain = tc.getConfig().getDefaultDomain();
        byte[] ti = TARGET_INFO_CACHE.get(domain);
        if ( ti != null ) {
            return ti;
        }

        ti = makeTargetInfo(tc, domain);
        TARGET_INFO_CACHE.put(domain, ti);
        return ti;
    }


    /**
     * @param domain
     * @param domainLength
     * @param server
     * @return
     */
    private static byte[] makeTargetInfo ( CIFSContext tc, String domainStr ) {
        byte[] domain = new byte[0];
        if ( domainStr != null ) {
            try {
                domain = domainStr.getBytes(UNI_ENCODING);
            }
            catch ( IOException ex ) {
                log.debug("Failed to get domain bytes", ex);
            }
        }
        int domainLength = domain.length;
        byte[] server = new byte[0];
        String host = tc.getNameServiceClient().getLocalHost().getHostName();
        if ( host != null ) {
            try {
                server = host.getBytes(UNI_ENCODING);
            }
            catch ( IOException ex ) {
                log.debug("Failed to get host bytes", ex);
            }
        }
        int serverLength = server.length;
        byte[] targetInfo = new byte[ ( domainLength > 0 ? domainLength + 4 : 0 ) + ( serverLength > 0 ? serverLength + 4 : 0 ) + 4];
        int offset = 0;
        if ( domainLength > 0 ) {
            writeUShort(targetInfo, offset, 2);
            offset += 2;
            writeUShort(targetInfo, offset, domainLength);
            offset += 2;
            System.arraycopy(domain, 0, targetInfo, offset, domainLength);
            offset += domainLength;
        }
        if ( serverLength > 0 ) {
            writeUShort(targetInfo, offset, 1);
            offset += 2;
            writeUShort(targetInfo, offset, serverLength);
            offset += 2;
            System.arraycopy(server, 0, targetInfo, offset, serverLength);
        }
        return targetInfo;
    }


    /**
     * Creates a Type-2 message using default values from the current
     * environment.
     * 
     * @param tc
     *            context to use
     */
    public Type2Message ( CIFSContext tc ) {
        this(tc, getDefaultFlags(tc), null, null);
    }


    /**
     * Creates a Type-2 message in response to the given Type-1 message
     * using default values from the current environment.
     * 
     * @param tc
     *            context to use
     * @param type1
     *            The Type-1 message which this represents a response to.
     */
    public Type2Message ( CIFSContext tc, Type1Message type1 ) {
        this(tc, type1, null, null);
    }


    /**
     * Creates a Type-2 message in response to the given Type-1 message.
     * 
     * @param tc
     *            context to use
     * @param type1
     *            The Type-1 message which this represents a response to.
     * @param challenge
     *            The challenge from the domain controller/server.
     * @param target
     *            The authentication target.
     */
    public Type2Message ( CIFSContext tc, Type1Message type1, byte[] challenge, String target ) {
        this(
            tc,
            getDefaultFlags(tc, type1),
            challenge,
            ( type1 != null && target == null && type1.getFlag(NTLMSSP_REQUEST_TARGET) ) ? tc.getConfig().getDefaultDomain() : target);
    }


    /**
     * Creates a Type-2 message with the specified parameters.
     * 
     * @param tc
     *            context to use
     * @param flags
     *            The flags to apply to this message.
     * @param challenge
     *            The challenge from the domain controller/server.
     * @param target
     *            The authentication target.
     */
    public Type2Message ( CIFSContext tc, int flags, byte[] challenge, String target ) {
        setFlags(flags);
        setChallenge(challenge);
        setTarget(target);
        if ( target != null ) {
            setTargetInformation(getDefaultTargetInfo(tc));
        }
    }


    /**
     * Creates a Type-2 message using the given raw Type-2 material.
     *
     * @param material
     *            The raw Type-2 material used to construct this message.
     * @throws IOException
     *             If an error occurs while parsing the material.
     */
    public Type2Message ( byte[] material ) throws IOException {
        parse(material);
    }


    /**
     * Returns the default flags for a generic Type-2 message in the
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
     * Returns the default flags for a Type-2 message created in response
     * to the given Type-1 message in the current environment.
     * 
     * @param tc
     *            context to use
     * @param type1
     *            request message
     *
     * @return An <code>int</code> containing the default flags.
     */
    public static int getDefaultFlags ( CIFSContext tc, Type1Message type1 ) {
        if ( type1 == null )
            return getDefaultFlags(tc);
        int flags = NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_VERSION;
        int type1Flags = type1.getFlags();
        flags |= ( ( type1Flags & NTLMSSP_NEGOTIATE_UNICODE ) != 0 ) ? NTLMSSP_NEGOTIATE_UNICODE : NTLMSSP_NEGOTIATE_OEM;
        if ( ( type1Flags & NTLMSSP_REQUEST_TARGET ) != 0 ) {
            String domain = tc.getConfig().getDefaultDomain();
            if ( domain != null ) {
                flags |= NTLMSSP_REQUEST_TARGET | NTLMSSP_TARGET_TYPE_DOMAIN;
            }
        }
        return flags;
    }


    /**
     * Returns the challenge for this message.
     *
     * @return A <code>byte[]</code> containing the challenge.
     */
    public byte[] getChallenge () {
        return this.challenge;
    }


    /**
     * Sets the challenge for this message.
     *
     * @param challenge
     *            The challenge from the domain controller/server.
     */
    public void setChallenge ( byte[] challenge ) {
        this.challenge = challenge;
    }


    /**
     * Returns the authentication target.
     *
     * @return A <code>String</code> containing the authentication target.
     */
    public String getTarget () {
        return this.target;
    }


    /**
     * Sets the authentication target.
     *
     * @param target
     *            The authentication target.
     */
    public void setTarget ( String target ) {
        this.target = target;
    }


    /**
     * Returns the target information block.
     *
     * @return A <code>byte[]</code> containing the target information block.
     *         The target information block is used by the client to create an
     *         NTLMv2 response.
     */
    public byte[] getTargetInformation () {
        return this.targetInformation;
    }


    /**
     * Sets the target information block.
     * The target information block is used by the client to create
     * an NTLMv2 response.
     * 
     * @param targetInformation
     *            The target information block.
     */
    public void setTargetInformation ( byte[] targetInformation ) {
        this.targetInformation = targetInformation;
    }


    /**
     * Returns the local security context.
     *
     * @return A <code>byte[]</code> containing the local security
     *         context. This is used by the client to negotiate local
     *         authentication.
     */
    public byte[] getContext () {
        return this.context;
    }


    /**
     * Sets the local security context. This is used by the client
     * to negotiate local authentication.
     *
     * @param context
     *            The local security context.
     */
    public void setContext ( byte[] context ) {
        this.context = context;
    }


    @Override
    public byte[] toByteArray () throws IOException {
        int size = 48;
        int flags = getFlags();
        String targetName = getTarget();
        byte[] targetInformationBytes = getTargetInformation();
        byte[] targetBytes = new byte[0];

        if ( getFlag(NTLMSSP_REQUEST_TARGET) ) {
            if ( targetName != null && targetName.length() != 0 ) {
                targetBytes = ( flags & NTLMSSP_NEGOTIATE_UNICODE ) != 0 ? targetName.getBytes(UNI_ENCODING)
                        : targetName.toUpperCase().getBytes(getOEMEncoding());
                size += targetBytes.length;
            }
            else {
                flags &= ( 0xffffffff ^ NTLMSSP_REQUEST_TARGET );
            }
        }

        if ( targetInformationBytes != null ) {
            size += targetInformationBytes.length;
            flags |= NTLMSSP_NEGOTIATE_TARGET_INFO;
        }

        if ( getFlag(NTLMSSP_NEGOTIATE_VERSION) ) {
            size += 8;
        }

        byte[] type2 = new byte[size];
        int pos = 0;

        System.arraycopy(NTLMSSP_SIGNATURE, 0, type2, pos, NTLMSSP_SIGNATURE.length);
        pos += NTLMSSP_SIGNATURE.length;

        writeULong(type2, pos, NTLMSSP_TYPE2);
        pos += 4;

        // TargetNameFields
        int targetNameOff = writeSecurityBuffer(type2, pos, targetBytes);
        pos += 8;

        writeULong(type2, pos, flags);
        pos += 4;

        // ServerChallenge
        byte[] challengeBytes = getChallenge();
        System.arraycopy(challengeBytes != null ? challengeBytes : new byte[8], 0, type2, pos, 8);
        pos += 8;

        // Reserved
        byte[] contextBytes = getContext();
        System.arraycopy(contextBytes != null ? contextBytes : new byte[8], 0, type2, pos, 8);
        pos += 8;

        // TargetInfoFields
        int targetInfoOff = writeSecurityBuffer(type2, pos, targetInformationBytes);
        pos += 8;

        if ( getFlag(NTLMSSP_NEGOTIATE_VERSION) ) {
            System.arraycopy(NTLMSSP_VERSION, 0, type2, pos, NTLMSSP_VERSION.length);
            pos += NTLMSSP_VERSION.length;
        }

        pos += writeSecurityBufferContent(type2, pos, targetNameOff, targetBytes);
        pos += writeSecurityBufferContent(type2, pos, targetInfoOff, targetInformationBytes);

        return type2;
    }


    @Override
    public String toString () {
        String targetString = getTarget();
        byte[] challengeBytes = getChallenge();
        byte[] contextBytes = getContext();
        byte[] targetInformationBytes = getTargetInformation();

        return "Type2Message[target=" + targetString + ",challenge=" + ( challengeBytes == null ? "null" : "<" + challengeBytes.length + " bytes>" )
                + ",context=" + ( contextBytes == null ? "null" : "<" + contextBytes.length + " bytes>" ) + ",targetInformation="
                + ( targetInformationBytes == null ? "null" : "<" + targetInformationBytes.length + " bytes>" ) + ",flags=0x"
                + jcifs.util.Hexdump.toHexString(getFlags(), 8) + "]";
    }


    private void parse ( byte[] input ) throws IOException {
        int pos = 0;
        for ( int i = 0; i < 8; i++ ) {
            if ( input[ i ] != NTLMSSP_SIGNATURE[ i ] ) {
                throw new IOException("Not an NTLMSSP message.");
            }
        }
        pos += 8;

        if ( readULong(input, pos) != NTLMSSP_TYPE2 ) {
            throw new IOException("Not a Type 2 message.");
        }
        pos += 4;

        int flags = readULong(input, pos + 8);
        setFlags(flags);

        byte[] targetName = readSecurityBuffer(input, pos);
        int targetNameOff = readULong(input, pos + 4);
        if ( targetName.length != 0 ) {
            setTarget(new String(targetName, ( ( flags & NTLMSSP_NEGOTIATE_UNICODE ) != 0 ) ? UNI_ENCODING : getOEMEncoding()));
        }
        pos += 12; // 8 for target, 4 for flags

        if ( !allZeros8(input, pos) ) {
            byte[] challengeBytes = new byte[8];
            System.arraycopy(input, pos, challengeBytes, 0, challengeBytes.length);
            setChallenge(challengeBytes);
        }
        pos += 8;

        if ( targetNameOff < pos + 8 || input.length < pos + 8 ) {
            // no room for Context/Reserved
            return;
        }

        if ( !allZeros8(input, pos) ) {
            byte[] contextBytes = new byte[8];
            System.arraycopy(input, pos, contextBytes, 0, contextBytes.length);
            setContext(contextBytes);
        }
        pos += 8;

        if ( targetNameOff < pos + 8 || input.length < pos + 8 ) {
            // no room for target info
            return;
        }

        byte[] targetInfo = readSecurityBuffer(input, pos);
        if ( targetInfo.length != 0 ) {
            setTargetInformation(targetInfo);
        }
    }


    private static boolean allZeros8 ( byte[] input, int pos ) {
        for ( int i = pos; i < pos + 8; i++ ) {
            if ( input[ i ] != 0 ) {
                return false;
            }
        }
        return true;
    }

}
