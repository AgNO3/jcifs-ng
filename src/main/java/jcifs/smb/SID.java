/* jcifs smb client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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


import java.io.IOException;
import java.util.StringTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.RuntimeCIFSException;
import jcifs.dcerpc.rpc;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;


/**
 * Internal representation of SIDs
 * 
 * A Windows SID is a numeric identifier used to represent Windows
 * accounts. SIDs are commonly represented using a textual format such as
 * <tt>S-1-5-21-1496946806-2192648263-3843101252-1029</tt> but they may
 * also be resolved to yield the name of the associated Windows account
 * such as <tt>Administrators</tt> or <tt>MYDOM\alice</tt>.
 * <p>
 * Consider the following output of <tt>examples/SidLookup.java</tt>:
 * 
 * <pre>
 *        toString: S-1-5-21-4133388617-793952518-2001621813-512
 * toDisplayString: WNET\Domain Admins
 *         getType: 2
 *     getTypeText: Domain group
 *   getDomainName: WNET
 *  getAccountName: Domain Admins
 * </pre>
 * 
 * @internal
 */
public class SID extends rpc.sid_t implements jcifs.SID {

    private static final Logger log = LoggerFactory.getLogger(SID.class);

    static final String[] SID_TYPE_NAMES = {
        "0", "User", "Domain group", "Domain", "Local group", "Builtin group", "Deleted", "Invalid", "Unknown"
    };

    /**
     * 
     */
    public static final int SID_FLAG_RESOLVE_SIDS = 0x0001;

    /**
     * Well known SID: EVERYONE
     */
    public static SID EVERYONE = null;

    /**
     * Well known SID: CREATOR_OWNER
     */
    public static SID CREATOR_OWNER = null;

    /**
     * Well known SID: SYSTEM
     */
    public static SID SYSTEM = null;

    static {
        try {
            EVERYONE = new SID("S-1-1-0");
            CREATOR_OWNER = new SID("S-1-3-0");
            SYSTEM = new SID("S-1-5-18");
        }
        catch ( SmbException se ) {
            log.error("Failed to create builtin SIDs", se);
        }
    }


    /**
     * Convert a sid_t to byte array
     * 
     * @param sid
     * @return byte encoded form
     */
    public static byte[] toByteArray ( rpc.sid_t sid ) {
        byte[] dst = new byte[1 + 1 + 6 + sid.sub_authority_count * 4];
        int di = 0;
        dst[ di++ ] = sid.revision;
        dst[ di++ ] = sid.sub_authority_count;
        System.arraycopy(sid.identifier_authority, 0, dst, di, 6);
        di += 6;
        for ( int ii = 0; ii < sid.sub_authority_count; ii++ ) {
            jcifs.util.Encdec.enc_uint32le(sid.sub_authority[ ii ], dst, di);
            di += 4;
        }
        return dst;
    }

    int type;
    String domainName = null;
    String acctName = null;
    String origin_server = null;
    CIFSContext origin_ctx = null;


    /**
     * Construct a SID from it's binary representation.
     *
     * 
     * @param src
     * @param si
     */
    public SID ( byte[] src, int si ) {
        this.revision = src[ si++ ];
        this.sub_authority_count = src[ si++ ];
        this.identifier_authority = new byte[6];
        System.arraycopy(src, si, this.identifier_authority, 0, 6);
        si += 6;
        if ( this.sub_authority_count > 100 )
            throw new RuntimeCIFSException("Invalid SID sub_authority_count");
        this.sub_authority = new int[this.sub_authority_count];
        for ( int i = 0; i < this.sub_authority_count; i++ ) {
            this.sub_authority[ i ] = SMBUtil.readInt4(src, si);
            si += 4;
        }
    }


    /**
     * Construct a SID from it's textual representation such as
     * <tt>S-1-5-21-1496946806-2192648263-3843101252-1029</tt>.
     * 
     * @param textual
     * @throws SmbException
     */
    public SID ( String textual ) throws SmbException {
        StringTokenizer st = new StringTokenizer(textual, "-");
        if ( st.countTokens() < 3 || !st.nextToken().equals("S") )
            // need S-N-M
            throw new SmbException("Bad textual SID format: " + textual);

        this.revision = Byte.parseByte(st.nextToken());
        String tmp = st.nextToken();
        long id = 0;
        if ( tmp.startsWith("0x") )
            id = Long.parseLong(tmp.substring(2), 16);
        else
            id = Long.parseLong(tmp);

        this.identifier_authority = new byte[6];
        for ( int i = 5; id > 0; i-- ) {
            this.identifier_authority[ i ] = (byte) ( id % 256 );
            id >>= 8;
        }

        this.sub_authority_count = (byte) st.countTokens();
        if ( this.sub_authority_count > 0 ) {
            this.sub_authority = new int[this.sub_authority_count];
            for ( int i = 0; i < this.sub_authority_count; i++ )
                this.sub_authority[ i ] = (int) ( Long.parseLong(st.nextToken()) & 0xFFFFFFFFL );
        }
    }


    /**
     * Construct a SID from a domain SID and an RID
     * (relative identifier). For example, a domain SID
     * <tt>S-1-5-21-1496946806-2192648263-3843101252</tt> and RID <tt>1029</tt> would
     * yield the SID <tt>S-1-5-21-1496946806-2192648263-3843101252-1029</tt>.
     * 
     * @param domsid
     * @param rid
     */
    public SID ( SID domsid, int rid ) {
        this.revision = domsid.revision;
        this.identifier_authority = domsid.identifier_authority;
        this.sub_authority_count = (byte) ( domsid.sub_authority_count + 1 );
        this.sub_authority = new int[this.sub_authority_count];
        int i;
        for ( i = 0; i < domsid.sub_authority_count; i++ ) {
            this.sub_authority[ i ] = domsid.sub_authority[ i ];
        }
        this.sub_authority[ i ] = rid;
    }


    /**
     * Construct a relative SID
     * 
     * @param domsid
     * @param id
     */
    public SID ( SID domsid, SID id ) {
        this.revision = domsid.revision;
        this.identifier_authority = domsid.identifier_authority;
        this.sub_authority_count = (byte) ( domsid.sub_authority_count + id.sub_authority_count );
        this.sub_authority = new int[this.sub_authority_count];
        int i;
        for ( i = 0; i < domsid.sub_authority_count; i++ ) {
            this.sub_authority[ i ] = domsid.sub_authority[ i ];
        }
        for ( i = domsid.sub_authority_count; i < domsid.sub_authority_count + id.sub_authority_count; i++ ) {
            this.sub_authority[ i ] = id.sub_authority[ i - domsid.sub_authority_count ];
        }
    }


    /**
     * 
     * @param sid
     * @param type
     * @param domainName
     * @param acctName
     * @param decrementAuthority
     */
    public SID ( rpc.sid_t sid, int type, String domainName, String acctName, boolean decrementAuthority ) {
        this.revision = sid.revision;
        this.sub_authority_count = sid.sub_authority_count;
        this.identifier_authority = sid.identifier_authority;
        this.sub_authority = sid.sub_authority;
        this.type = type;
        this.domainName = domainName;
        this.acctName = acctName;

        if ( decrementAuthority ) {
            this.sub_authority_count--;
            this.sub_authority = new int[this.sub_authority_count];
            for ( int i = 0; i < this.sub_authority_count; i++ ) {
                this.sub_authority[ i ] = sid.sub_authority[ i ];
            }
        }
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.SID#unwrap(java.lang.Class)
     */
    @SuppressWarnings ( "unchecked" )
    @Override
    public <T> T unwrap ( Class<T> t ) {
        if ( t.isAssignableFrom(this.getClass()) ) {
            return (T) this;
        }
        throw new ClassCastException();
    }


    /**
     * 
     * @return encoded SID
     */
    public byte[] toByteArray () {
        return toByteArray(this);
    }


    /**
     * 
     * @return whether the SID is empty (no sub-authorities)
     */
    public boolean isEmpty () {
        return this.sub_authority_count == 0;
    }


    /**
     * 
     * @return whether the SID is blank (all sub-authorities zero)
     */
    public boolean isBlank () {
        boolean blank = true;
        for ( int sub : this.sub_authority )
            blank = blank && ( sub == 0 );
        return blank;
    }


    /**
     * 
     * @return domain SID
     */
    @Override
    public SID getDomainSid () {
        return new SID(this, SID_TYPE_DOMAIN, this.domainName, null, getType() != SID_TYPE_DOMAIN);
    }


    /**
     * Get the RID
     * 
     * This is the last subauthority identifier
     * 
     * @return the RID
     */
    @Override
    public int getRid () {
        if ( getType() == SID_TYPE_DOMAIN )
            throw new IllegalArgumentException("This SID is a domain sid");
        return this.sub_authority[ this.sub_authority_count - 1 ];
    }


    @Override
    public int getType () {
        if ( this.origin_server != null )
            resolveWeak();
        return this.type;
    }


    @Override
    public String getTypeText () {
        if ( this.origin_server != null )
            resolveWeak();
        return SID_TYPE_NAMES[ this.type ];
    }


    @Override
    public String getDomainName () {
        if ( this.origin_server != null )
            resolveWeak();
        if ( this.type == SID_TYPE_UNKNOWN ) {
            String full = toString();
            return full.substring(0, full.length() - getAccountName().length() - 1);
        }
        return this.domainName;
    }


    @Override
    public String getAccountName () {
        if ( this.origin_server != null )
            resolveWeak();
        if ( this.type == SID_TYPE_UNKNOWN )
            return "" + this.sub_authority[ this.sub_authority_count - 1 ];
        if ( this.type == SID_TYPE_DOMAIN )
            return "";
        return this.acctName;
    }


    @Override
    public int hashCode () {
        int hcode = this.identifier_authority[ 5 ];
        for ( int i = 0; i < this.sub_authority_count; i++ ) {
            hcode += 65599 * this.sub_authority[ i ];
        }
        return hcode;
    }


    @Override
    public boolean equals ( Object obj ) {
        if ( obj instanceof SID ) {
            SID sid = (SID) obj;
            if ( sid == this )
                return true;
            if ( sid.sub_authority_count == this.sub_authority_count ) {
                int i = this.sub_authority_count;
                while ( i-- > 0 ) {
                    if ( sid.sub_authority[ i ] != this.sub_authority[ i ] ) {
                        return false;
                    }
                }
                for ( i = 0; i < 6; i++ ) {
                    if ( sid.identifier_authority[ i ] != this.identifier_authority[ i ] ) {
                        return false;
                    }
                }

                return sid.revision == this.revision;
            }
        }
        return false;
    }


    /**
     * Return the numeric representation of this sid such as
     * <tt>S-1-5-21-1496946806-2192648263-3843101252-1029</tt>.
     */
    @Override
    public String toString () {
        String ret = "S-" + ( this.revision & 0xFF ) + "-";

        if ( this.identifier_authority[ 0 ] != (byte) 0 || this.identifier_authority[ 1 ] != (byte) 0 ) {
            ret += "0x";
            ret += Hexdump.toHexString(this.identifier_authority, 0, 6);
        }
        else {
            long shift = 0;
            long id = 0;
            for ( int i = 5; i > 1; i-- ) {
                id += ( this.identifier_authority[ i ] & 0xFFL ) << shift;
                shift += 8;
            }
            ret += id;
        }

        for ( int i = 0; i < this.sub_authority_count; i++ )
            ret += "-" + ( this.sub_authority[ i ] & 0xFFFFFFFFL );

        return ret;
    }


    @Override
    public String toDisplayString () {
        if ( this.origin_server != null )
            resolveWeak();
        if ( this.domainName != null ) {
            String str;

            if ( this.type == SID_TYPE_DOMAIN ) {
                str = this.domainName;
            }
            else if ( this.type == SID_TYPE_WKN_GRP || this.domainName.equals("BUILTIN") ) {
                if ( this.type == SID_TYPE_UNKNOWN ) {
                    str = toString();
                }
                else {
                    str = this.acctName;
                }
            }
            else {
                str = this.domainName + "\\" + this.acctName;
            }

            return str;
        }
        return toString();
    }


    /**
     * Manually resolve this SID. Normally SIDs are automatically
     * resolved. However, if a SID is constructed explicitly using a SID
     * constructor, JCIFS will have no knowledge of the server that created the
     * SID and therefore cannot possibly resolve it automatically. In this case,
     * this method will be necessary.
     * 
     * @param authorityServerName
     *            The FQDN of the server that is an authority for the SID.
     * @param tc
     *            Context to use
     * @throws IOException
     */
    public void resolve ( String authorityServerName, CIFSContext tc ) throws IOException {
        SID[] sids = new SID[1];
        sids[ 0 ] = this;
        tc.getSIDResolver().resolveSids(tc, authorityServerName, sids);
    }


    void resolveWeak () {
        if ( this.origin_server != null ) {
            try {
                resolve(this.origin_server, this.origin_ctx);
            }
            catch ( IOException ioe ) {
                log.debug("Failed to resolve SID", ioe);
            }
            finally {
                this.origin_server = null;
                this.origin_ctx = null;
            }
        }
    }


    /**
     * Get members of the group represented by this SID, if it is one.
     * 
     * @param authorityServerName
     * @param tc
     * @param flags
     * @return the members of the group
     * @throws IOException
     */
    public jcifs.SID[] getGroupMemberSids ( String authorityServerName, CIFSContext tc, int flags ) throws IOException {
        if ( this.type != SID_TYPE_DOM_GRP && this.type != SID_TYPE_ALIAS )
            return new SID[0];

        return tc.getSIDResolver().getGroupMemberSids(tc, authorityServerName, getDomainSid(), getRid(), flags);
    }


    /**
     * @param context
     * @param server
     */
    public void initContext ( String server, CIFSContext context ) {
        this.origin_ctx = context;
        this.origin_server = server;
    }

}
