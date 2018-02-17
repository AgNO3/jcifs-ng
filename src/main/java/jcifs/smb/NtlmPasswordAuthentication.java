/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                  "Eric Glass" <jcifs at samba dot org>
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


import java.security.GeneralSecurityException;
import java.util.Arrays;

import jcifs.CIFSContext;


/**
 * This class stores and encrypts NTLM user credentials. The default
 * credentials are retrieved from the <tt>jcifs.smb.client.domain</tt>,
 * <tt>jcifs.smb.client.username</tt>, and <tt>jcifs.smb.client.password</tt>
 * properties.
 * <p>
 * Read <a href="../../../authhandler.html">jCIFS Exceptions and
 * NtlmAuthenticator</a> for related information.
 */
@Deprecated
public class NtlmPasswordAuthentication extends NtlmPasswordAuthenticator {

    /**
     * 
     */
    private static final long serialVersionUID = -2832037191318016836L;

    private byte[] ansiHash;
    private byte[] unicodeHash;
    private boolean hashesExternal = false;
    private CIFSContext context;


    /**
     * 
     */
    private NtlmPasswordAuthentication () {}


    /**
     * Construct anonymous credentials
     * 
     * @param tc
     */
    public NtlmPasswordAuthentication ( CIFSContext tc ) {
        this(tc, "", "", "");
    }


    /**
     * Create an <tt>NtlmPasswordAuthentication</tt> object from the userinfo
     * component of an SMB URL like "<tt>domain;user:pass</tt>". This constructor
     * is used internally be jCIFS when parsing SMB URLs.
     * 
     * @param tc
     * @param userInfo
     */
    public NtlmPasswordAuthentication ( CIFSContext tc, String userInfo ) {
        super(
            userInfo,
            tc.getConfig().getDefaultDomain(),
            tc.getConfig().getDefaultUsername() != null ? tc.getConfig().getDefaultUsername() : "GUEST",
            tc.getConfig().getDefaultPassword() != null ? tc.getConfig().getDefaultPassword() : "");
        this.context = tc;
    }


    /**
     * Create an <tt>NtlmPasswordAuthentication</tt> object from a
     * domain, username, and password. Parameters that are <tt>null</tt>
     * will be substituted with <tt>jcifs.smb.client.domain</tt>,
     * <tt>jcifs.smb.client.username</tt>, <tt>jcifs.smb.client.password</tt>
     * property values.
     * 
     * @param tc
     *            context to use
     * @param domain
     * @param username
     * @param password
     */
    public NtlmPasswordAuthentication ( CIFSContext tc, String domain, String username, String password ) {
        super(
            domain != null ? domain : tc.getConfig().getDefaultDomain(),
            username != null ? username : ( tc.getConfig().getDefaultUsername() != null ? tc.getConfig().getDefaultUsername() : "GUEST" ),
            password != null ? password : ( tc.getConfig().getDefaultPassword() != null ? tc.getConfig().getDefaultPassword() : "" ));
        this.context = tc;
    }


    /**
     * Create an <tt>NtlmPasswordAuthentication</tt> object with raw password
     * hashes. This is used exclusively by the <tt>jcifs.http.NtlmSsp</tt>
     * class which is in turn used by NTLM HTTP authentication functionality.
     * 
     * @param domain
     * @param username
     * @param challenge
     * @param ansiHash
     * @param unicodeHash
     */
    public NtlmPasswordAuthentication ( String domain, String username, byte[] challenge, byte[] ansiHash, byte[] unicodeHash ) {
        super(domain, username, null);
        if ( domain == null || username == null || ansiHash == null || unicodeHash == null ) {
            throw new IllegalArgumentException("External credentials cannot be null");
        }
        this.ansiHash = ansiHash;
        this.unicodeHash = unicodeHash;
        this.hashesExternal = true;
    }


    protected CIFSContext getContext () {
        return this.context;
    }


    @Override
    public NtlmPasswordAuthentication clone () {
        NtlmPasswordAuthentication cloned = new NtlmPasswordAuthentication();
        cloneInternal(cloned, this);
        return cloned;
    }


    /**
     * @param to
     * @param from
     */
    protected static void cloneInternal ( NtlmPasswordAuthentication to, NtlmPasswordAuthentication from ) {
        to.context = from.context;
        if ( from.hashesExternal ) {
            to.hashesExternal = true;
            to.ansiHash = from.ansiHash != null ? Arrays.copyOf(from.ansiHash, from.ansiHash.length) : null;
            to.unicodeHash = from.unicodeHash != null ? Arrays.copyOf(from.unicodeHash, from.unicodeHash.length) : null;
        }
        else {
            NtlmPasswordAuthenticator.cloneInternal(to, from);
        }
    }


    /**
     * Compares two <tt>NtlmPasswordAuthentication</tt> objects for
     * equality. Two <tt>NtlmPasswordAuthentication</tt> objects are equal if
     * their caseless domain and username fields are equal and either both hashes are external and they are equal or
     * both internally supplied passwords are equal. If one <tt>NtlmPasswordAuthentication</tt> object has external
     * hashes (meaning negotiated via NTLM HTTP Authentication) and the other does not they will not be equal. This is
     * technically not correct however the server 8 byte challenge would be required to compute and compare the password
     * hashes but that it not available with this method.
     */
    @Override
    public boolean equals ( Object obj ) {
        if ( super.equals(obj) ) {
            if ( ! ( obj instanceof NtlmPasswordAuthentication ) ) {
                return !this.areHashesExternal();
            }
            NtlmPasswordAuthentication ntlm = (NtlmPasswordAuthentication) obj;
            if ( this.areHashesExternal() && ntlm.areHashesExternal() ) {
                return Arrays.equals(this.ansiHash, ntlm.ansiHash) && Arrays.equals(this.unicodeHash, ntlm.unicodeHash);
                /*
                 * This still isn't quite right. If one npa object does not have external
                 * hashes and the other does then they will not be considered equal even
                 * though they may be.
                 */
            }
            return true;
        }
        return false;
    }


    /**
     * @return whether the hashes are externally supplied
     */
    public boolean areHashesExternal () {
        return this.hashesExternal;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.NtlmPasswordAuthenticator#getAnsiHash(jcifs.CIFSContext, byte[])
     */
    @Override
    public byte[] getAnsiHash ( CIFSContext tc, byte[] chlng ) throws GeneralSecurityException {
        if ( this.hashesExternal ) {
            return this.ansiHash;
        }
        return super.getAnsiHash(tc, chlng);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.NtlmPasswordAuthenticator#getUnicodeHash(jcifs.CIFSContext, byte[])
     */
    @Override
    public byte[] getUnicodeHash ( CIFSContext tc, byte[] chlng ) throws GeneralSecurityException {
        if ( this.hashesExternal ) {
            return this.unicodeHash;
        }
        return super.getUnicodeHash(tc, chlng);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.NtlmPasswordAuthenticator#getUserSessionKey(jcifs.CIFSContext, byte[])
     */
    @Override
    public byte[] getUserSessionKey ( CIFSContext tc, byte[] chlng ) {
        if ( this.hashesExternal ) {
            return null;
        }
        return super.getUserSessionKey(tc, chlng);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.NtlmPasswordAuthenticator#getUserSessionKey(jcifs.CIFSContext, byte[], byte[], int)
     */
    @Override
    public void getUserSessionKey ( CIFSContext tc, byte[] chlng, byte[] dest, int offset ) throws SmbException {
        if ( this.hashesExternal ) {
            return;
        }
        super.getUserSessionKey(tc, chlng, dest, offset);
    }
}
