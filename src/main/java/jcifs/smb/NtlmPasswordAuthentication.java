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


import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.Subject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Credentials;
import jcifs.RuntimeCIFSException;
import jcifs.util.Crypto;
import jcifs.util.Strings;


/**
 * This class stores and encrypts NTLM user credentials. The default
 * credentials are retrieved from the <tt>jcifs.smb.client.domain</tt>,
 * <tt>jcifs.smb.client.username</tt>, and <tt>jcifs.smb.client.password</tt>
 * properties.
 * <p>
 * Read <a href="../../../authhandler.html">jCIFS Exceptions and
 * NtlmAuthenticator</a> for related information.
 */

public class NtlmPasswordAuthentication implements Principal, CredentialsInternal, Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -2832037191318016836L;

    private static final Logger log = LoggerFactory.getLogger(NtlmPasswordAuthentication.class);

    private String domain;
    private String username;
    private String password;
    private byte[] ansiHash;
    private byte[] unicodeHash;
    private boolean hashesExternal = false;
    private byte[] clientChallenge = null;

    private boolean nullAuth;
    private CIFSContext context;


    /**
     * 
     */
    private NtlmPasswordAuthentication () {}


    @SuppressWarnings ( "unchecked" )
    @Override
    public <T extends Credentials> T unwrap ( Class<T> type ) {
        if ( type.isAssignableFrom(this.getClass()) ) {
            return (T) this;
        }
        return null;
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
        this.context = tc;
        int ci;

        if ( username != null ) {
            ci = username.indexOf('@');
            if ( ci > 0 ) {
                domain = username.substring(ci + 1);
                username = username.substring(0, ci);
            }
            else {
                ci = username.indexOf('\\');
                if ( ci > 0 ) {
                    domain = username.substring(0, ci);
                    username = username.substring(ci + 1);
                }
            }
        }

        this.domain = domain;
        this.username = username;
        this.password = password;

        setupDefaults(tc);
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
        if ( domain == null || username == null || ansiHash == null || unicodeHash == null ) {
            throw new IllegalArgumentException("External credentials cannot be null");
        }
        this.domain = domain;
        this.username = username;
        this.password = null;
        this.ansiHash = ansiHash;
        this.unicodeHash = unicodeHash;
        this.hashesExternal = true;
    }


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
        this.domain = this.username = this.password = null;

        if ( userInfo != null ) {
            try {
                userInfo = unescape(userInfo);
            }
            catch ( UnsupportedEncodingException uee ) {
                throw new RuntimeCIFSException(uee);
            }
            int i, u, end;
            char c;

            end = userInfo.length();
            for ( i = 0, u = 0; i < end; i++ ) {
                c = userInfo.charAt(i);
                if ( c == ';' ) {
                    this.domain = userInfo.substring(0, i);
                    u = i + 1;
                }
                else if ( c == ':' ) {
                    this.password = userInfo.substring(i + 1);
                    break;
                }
            }
            this.username = userInfo.substring(u, i);
        }

        setupDefaults(tc);
    }


    protected CIFSContext getContext () {
        return this.context;
    }


    @Override
    public Subject getSubject () {
        return null;
    }


    @Override
    public void refresh () throws CIFSException {}


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.CredentialsInternal#createContext(jcifs.CIFSContext, java.lang.String, java.lang.String, byte[],
     *      boolean)
     */
    @Override
    public SSPContext createContext ( CIFSContext transportContext, String targetDomain, String host, byte[] initialToken, boolean doSigning )
            throws SmbException {
        return new NtlmContext(transportContext, this, doSigning);
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
        to.domain = from.domain;
        to.username = from.username;
        to.password = from.password;
        to.nullAuth = from.nullAuth;

        if ( from.hashesExternal ) {
            to.hashesExternal = true;
            to.ansiHash = from.ansiHash != null ? Arrays.copyOf(from.ansiHash, from.ansiHash.length) : null;
            to.unicodeHash = from.unicodeHash != null ? Arrays.copyOf(from.unicodeHash, from.unicodeHash.length) : null;
        }

    }


    /**
     * @param tc
     */
    private void setupDefaults ( CIFSContext tc ) {
        if ( this.domain == null )
            this.domain = tc.getConfig().getDefaultDomain();
        if ( this.username == null )
            this.username = tc.getConfig().getDefaultUsername() != null ? tc.getConfig().getDefaultUsername() : "GUEST";
        if ( this.password == null )
            this.password = tc.getConfig().getDefaultPassword() != null ? tc.getConfig().getDefaultPassword() : "";
    }


    /**
     * Returns the domain.
     */
    @Override
    public String getUserDomain () {
        return this.domain;
    }


    /**
     * 
     * @return the original specified user domain
     */
    public String getSpecifiedUserDomain () {
        return this.domain;
    }


    /**
     * Returns the username.
     * 
     * @return the username
     */
    public String getUsername () {
        return this.username;
    }


    /**
     * Returns the password in plain text or <tt>null</tt> if the raw password
     * hashes were used to construct this <tt>NtlmPasswordAuthentication</tt>
     * object which will be the case when NTLM HTTP Authentication is
     * used. There is no way to retrieve a users password in plain text unless
     * it is supplied by the user at runtime.
     * 
     * @return the password
     */
    public String getPassword () {
        return this.password;
    }


    /**
     * Return the domain and username in the format:
     * <tt>domain\\username</tt>. This is equivalent to <tt>toString()</tt>.
     */
    @Override
    public String getName () {
        boolean d = this.domain != null && this.domain.length() > 0;
        return d ? this.domain + "\\" + this.username : this.username;
    }


    /**
     * Computes the 24 byte ANSI password hash given the 8 byte server challenge.
     * 
     * @param tc
     * @param chlng
     * @return the hash for the given challenge
     * @throws GeneralSecurityException
     */
    public byte[] getAnsiHash ( CIFSContext tc, byte[] chlng ) throws GeneralSecurityException {
        if ( this.hashesExternal ) {
            return this.ansiHash;
        }
        switch ( tc.getConfig().getLanManCompatibility() ) {
        case 0:
        case 1:
            return NtlmUtil.getPreNTLMResponse(tc, this.password, chlng);
        case 2:
            return NtlmUtil.getNTLMResponse(this.password, chlng);
        case 3:
        case 4:
        case 5:
            if ( this.clientChallenge == null ) {
                this.clientChallenge = new byte[8];
                tc.getConfig().getRandom().nextBytes(this.clientChallenge);
            }
            return NtlmUtil.getLMv2Response(this.domain, this.username, this.password, chlng, this.clientChallenge);
        default:
            return NtlmUtil.getPreNTLMResponse(tc, this.password, chlng);
        }
    }


    /**
     * Computes the 24 byte Unicode password hash given the 8 byte server challenge.
     * 
     * @param tc
     * @param chlng
     * @return the hash for the given challenge
     * @throws GeneralSecurityException
     */
    public byte[] getUnicodeHash ( CIFSContext tc, byte[] chlng ) throws GeneralSecurityException {
        if ( this.hashesExternal ) {
            return this.unicodeHash;
        }
        switch ( tc.getConfig().getLanManCompatibility() ) {
        case 0:
        case 1:
        case 2:
            return NtlmUtil.getNTLMResponse(this.password, chlng);
        case 3:
        case 4:
        case 5:
            return new byte[0];
        default:
            return NtlmUtil.getNTLMResponse(this.password, chlng);
        }
    }


    /**
     * @param tc
     * @param chlng
     * @return the signing key
     * @throws SmbException
     * @throws GeneralSecurityException
     */
    public byte[] getSigningKey ( CIFSContext tc, byte[] chlng ) throws SmbException, GeneralSecurityException {
        switch ( tc.getConfig().getLanManCompatibility() ) {
        case 0:
        case 1:
        case 2:
            byte[] signingKey = new byte[40];
            getUserSessionKey(tc, chlng, signingKey, 0);
            System.arraycopy(getUnicodeHash(tc, chlng), 0, signingKey, 16, 24);
            return signingKey;
        case 3:
        case 4:
        case 5:
            /*
             * This code is only called if extended security is not on. This will
             * all be cleaned up an normalized in JCIFS 2.x.
             */
            throw new SmbException(
                "NTLMv2 requires extended security (jcifs.smb.client.useExtendedSecurity must be true if jcifs.smb.lmCompatibility >= 3)");
        }
        return null;
    }


    /**
     * Returns the effective user session key.
     * 
     * @param tc
     * @param chlng
     *            The server challenge.
     * @return A <code>byte[]</code> containing the effective user session key,
     *         used in SMB MAC signing and NTLMSSP signing and sealing.
     */
    public byte[] getUserSessionKey ( CIFSContext tc, byte[] chlng ) {
        if ( this.hashesExternal )
            return null;
        byte[] key = new byte[16];
        try {
            getUserSessionKey(tc, chlng, key, 0);
        }
        catch ( Exception ex ) {
            log.error("Failed to get session key", ex);
        }
        return key;
    }


    /**
     * Calculates the effective user session key.
     *
     * @param tc
     *            context to use
     * @param chlng
     *            The server challenge.
     * @param dest
     *            The destination array in which the user session key will be
     *            placed.
     * @param offset
     *            The offset in the destination array at which the
     *            session key will start.
     * @throws SmbException
     */
    public void getUserSessionKey ( CIFSContext tc, byte[] chlng, byte[] dest, int offset ) throws SmbException {
        if ( this.hashesExternal )
            return;
        try {
            MessageDigest md4 = Crypto.getMD4();
            md4.update(Strings.getUNIBytes(this.password));
            switch ( tc.getConfig().getLanManCompatibility() ) {
            case 0:
            case 1:
            case 2:
                md4.update(md4.digest());
                md4.digest(dest, offset, 16);
                break;
            case 3:
            case 4:
            case 5:
                if ( this.clientChallenge == null ) {
                    this.clientChallenge = new byte[8];
                    tc.getConfig().getRandom().nextBytes(this.clientChallenge);
                }

                MessageDigest hmac = Crypto.getHMACT64(md4.digest());
                hmac.update(Strings.getUNIBytes(this.username.toUpperCase()));
                hmac.update(Strings.getUNIBytes(this.domain.toUpperCase()));
                byte[] ntlmv2Hash = hmac.digest();
                hmac = Crypto.getHMACT64(ntlmv2Hash);
                hmac.update(chlng);
                hmac.update(this.clientChallenge);
                MessageDigest userKey = Crypto.getHMACT64(ntlmv2Hash);
                userKey.update(hmac.digest());
                userKey.digest(dest, offset, 16);
                break;
            default:
                md4.update(md4.digest());
                md4.digest(dest, offset, 16);
                break;
            }
        }
        catch ( Exception e ) {
            throw new SmbException("", e);
        }
    }


    /**
     * Compares two <tt>NtlmPasswordAuthentication</tt> objects for
     * equality. Two <tt>NtlmPasswordAuthentication</tt> objects are equal if
     * their caseless domain and username fields are equal and either both hashes are external and they are equal or
     * both internally supplied passwords are equal. If one <tt>NtlmPasswordAuthentication</tt> object has external
     * hashes (meaning negotiated via NTLM HTTP Authentication) and the other does not they will not be equal. This is
     * technically not correct however the server 8 byte challage would be required to compute and compare the password
     * hashes but that it not available with this method.
     */
    @Override
    public boolean equals ( Object obj ) {
        if ( obj instanceof NtlmPasswordAuthentication ) {
            NtlmPasswordAuthentication ntlm = (NtlmPasswordAuthentication) obj;
            String domA = ntlm.getUserDomain() != null ? ntlm.getUserDomain().toUpperCase() : null;
            String domB = this.getUserDomain() != null ? this.getUserDomain().toUpperCase() : null;
            if ( Objects.equals(domA, domB) && ntlm.getUsername().equalsIgnoreCase(this.getUsername()) ) {
                if ( this.areHashesExternal() && ntlm.areHashesExternal() ) {
                    return Arrays.equals(this.ansiHash, ntlm.ansiHash) && Arrays.equals(this.unicodeHash, ntlm.unicodeHash);
                    /*
                     * This still isn't quite right. If one npa object does not have external
                     * hashes and the other does then they will not be considered equal even
                     * though they may be.
                     */
                }
                else if ( !this.areHashesExternal() && this.getPassword().equals(ntlm.getPassword()) ) {
                    return true;
                }
            }
        }
        return false;
    }


    /**
     * Return the upcased username hash code.
     */
    @Override
    public int hashCode () {
        return getName().toUpperCase().hashCode();
    }


    /**
     * Return the domain and username in the format:
     * <tt>domain\\username</tt>. This is equivalent to <tt>getName()</tt>.
     */
    @Override
    public String toString () {
        return getName();
    }


    @Override
    public boolean isAnonymous () {
        return ( getUserDomain() == null || getUserDomain().isEmpty() ) && ( getUsername().isEmpty() || isGuest() ) && getPassword().isEmpty();
    }


    @Override
    public boolean isGuest () {
        return "GUEST".equalsIgnoreCase(getUsername());
    }


    static String unescape ( String str ) throws NumberFormatException, UnsupportedEncodingException {
        char ch;
        int i, j, state, len;
        char[] out;
        byte[] b = new byte[1];

        if ( str == null ) {
            return null;
        }

        len = str.length();
        out = new char[len];
        state = 0;
        for ( i = j = 0; i < len; i++ ) {
            switch ( state ) {
            case 0:
                ch = str.charAt(i);
                if ( ch == '%' ) {
                    state = 1;
                }
                else {
                    out[ j++ ] = ch;
                }
                break;
            case 1:
                /*
                 * Get ASCII hex value and convert to platform dependant
                 * encoding like EBCDIC perhaps
                 */
                b[ 0 ] = (byte) ( Integer.parseInt(str.substring(i, i + 2), 16) & 0xFF );
                out[ j++ ] = ( new String(b, 0, 1, "ASCII") ).charAt(0);
                i++;
                state = 0;
            }
        }

        return new String(out, 0, j);
    }


    /**
     * @return whether the hashes are externally supplied
     */
    public boolean areHashesExternal () {
        return this.hashesExternal;
    }

}
