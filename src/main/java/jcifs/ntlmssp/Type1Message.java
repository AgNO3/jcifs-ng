/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

import jcifs.CIFSContext;


/**
 * Represents an NTLMSSP Type-1 message.
 */
public class Type1Message extends NtlmMessage {

    private String suppliedDomain;
    private String suppliedWorkstation;


    /**
     * Creates a Type-1 message using default values from the current
     * environment.
     * 
     * @param tc
     *            context to use
     */
    public Type1Message ( CIFSContext tc ) {
        this(tc, getDefaultFlags(tc), tc.getConfig().getDefaultDomain(), tc.getNameServiceClient().getLocalHost().getHostName());
    }


    /**
     * Creates a Type-1 message with the specified parameters.
     * 
     * @param tc
     *            context to use
     * @param flags
     *            The flags to apply to this message.
     * @param suppliedDomain
     *            The supplied authentication domain.
     * @param suppliedWorkstation
     *            The supplied workstation name.
     */
    public Type1Message ( CIFSContext tc, int flags, String suppliedDomain, String suppliedWorkstation ) {
        setFlags(getDefaultFlags(tc) | flags);
        setSuppliedDomain(suppliedDomain);
        setSuppliedWorkstation(suppliedWorkstation);
    }


    /**
     * Creates a Type-1 message using the given raw Type-1 material.
     *
     * @param material
     *            The raw Type-1 material used to construct this message.
     * @throws IOException
     *             If an error occurs while parsing the material.
     */
    public Type1Message ( byte[] material ) throws IOException {
        parse(material);
    }


    /**
     * Returns the default flags for a generic Type-1 message in the
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
     * Returns the supplied authentication domain.
     *
     * @return A <code>String</code> containing the supplied domain.
     */
    public String getSuppliedDomain () {
        return this.suppliedDomain;
    }


    /**
     * Sets the supplied authentication domain for this message.
     *
     * @param suppliedDomain
     *            The supplied domain for this message.
     */
    public void setSuppliedDomain ( String suppliedDomain ) {
        this.suppliedDomain = suppliedDomain;
    }


    /**
     * Returns the supplied workstation name.
     * 
     * @return A <code>String</code> containing the supplied workstation name.
     */
    public String getSuppliedWorkstation () {
        return this.suppliedWorkstation;
    }


    /**
     * Sets the supplied workstation name for this message.
     * 
     * @param suppliedWorkstation
     *            The supplied workstation for this message.
     */
    public void setSuppliedWorkstation ( String suppliedWorkstation ) {
        this.suppliedWorkstation = suppliedWorkstation;
    }


    @Override
    public byte[] toByteArray () {
        try {
            int flags = getFlags();
            int size = 8 * 4 + ( ( flags & NTLMSSP_NEGOTIATE_VERSION ) != 0 ? 8 : 0 );

            byte[] domain = new byte[0];
            String suppliedDomainString = getSuppliedDomain();
            if ( ( flags & NTLMSSP_NEGOTIATE_VERSION ) == 0 && suppliedDomainString != null && suppliedDomainString.length() != 0 ) {
                flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
                domain = suppliedDomainString.toUpperCase().getBytes(getOEMEncoding());
                size += domain.length;
            }
            else {
                flags &= ( NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED ^ 0xffffffff );
            }

            byte[] workstation = new byte[0];
            String suppliedWorkstationString = getSuppliedWorkstation();
            if ( ( flags & NTLMSSP_NEGOTIATE_VERSION ) == 0 && suppliedWorkstationString != null && suppliedWorkstationString.length() != 0 ) {
                flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
                workstation = suppliedWorkstationString.toUpperCase().getBytes(getOEMEncoding());
                size += workstation.length;
            }
            else {
                flags &= ( NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED ^ 0xffffffff );
            }

            byte[] type1 = new byte[size];
            int pos = 0;

            System.arraycopy(NTLMSSP_SIGNATURE, 0, type1, 0, NTLMSSP_SIGNATURE.length);
            pos += NTLMSSP_SIGNATURE.length;

            writeULong(type1, pos, NTLMSSP_TYPE1);
            pos += 4;

            writeULong(type1, pos, flags);
            pos += 4;

            int domOffOff = writeSecurityBuffer(type1, pos, domain);
            pos += 8;

            int wsOffOff = writeSecurityBuffer(type1, pos, workstation);
            pos += 8;

            if ( ( flags & NTLMSSP_NEGOTIATE_VERSION ) != 0 ) {
                System.arraycopy(NTLMSSP_VERSION, 0, type1, pos, NTLMSSP_VERSION.length);
                pos += NTLMSSP_VERSION.length;
            }

            pos += writeSecurityBufferContent(type1, pos, domOffOff, domain);
            pos += writeSecurityBufferContent(type1, pos, wsOffOff, workstation);
            return type1;
        }
        catch ( IOException ex ) {
            throw new IllegalStateException(ex.getMessage());
        }
    }


    @Override
    public String toString () {
        String suppliedDomainString = getSuppliedDomain();
        String suppliedWorkstationString = getSuppliedWorkstation();
        return "Type1Message[suppliedDomain=" + ( suppliedDomainString == null ? "null" : suppliedDomainString ) + ",suppliedWorkstation="
                + ( suppliedWorkstationString == null ? "null" : suppliedWorkstationString ) + ",flags=0x"
                + jcifs.util.Hexdump.toHexString(getFlags(), 8) + "]";
    }


    private void parse ( byte[] material ) throws IOException {
        int pos = 0;
        for ( int i = 0; i < 8; i++ ) {
            if ( material[ i ] != NTLMSSP_SIGNATURE[ i ] ) {
                throw new IOException("Not an NTLMSSP message.");
            }
        }
        pos += 8;

        if ( readULong(material, pos) != NTLMSSP_TYPE1 ) {
            throw new IOException("Not a Type 1 message.");
        }
        pos += 4;

        int flags = readULong(material, pos);
        setFlags(flags);
        pos += 4;

        if ( ( flags & NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED ) != 0 ) {
            byte[] domain = readSecurityBuffer(material, pos);
            setSuppliedDomain(new String(domain, getOEMEncoding()));
        }
        pos += 8;

        if ( ( flags & NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED ) != 0 ) {
            byte[] workstation = readSecurityBuffer(material, pos);
            setSuppliedWorkstation(new String(workstation, getOEMEncoding()));
        }
        pos += 8;
    }

}
