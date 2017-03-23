/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.netbios;


import java.net.InetAddress;
import java.net.UnknownHostException;

import jcifs.Address;
import jcifs.CIFSContext;


/**
 * <p>
 * Under normal conditions it is not necessary to use
 * this class to use jCIFS properly. Name resolusion is
 * handled internally to the <code>jcifs.smb</code> package.
 * <p>
 * This class is a wrapper for both {@link jcifs.netbios.NbtAddress}
 * and {@link java.net.InetAddress}. The name resolution mechanisms
 * used will systematically query all available configured resolution
 * services including WINS, broadcasts, DNS, and LMHOSTS. See
 * <a href="../../resolver.html">Setting Name Resolution Properties</a>
 * and the <code>jcifs.resolveOrder</code> property. Changing
 * jCIFS name resolution properties can greatly affect the behavior of
 * the client and may be necessary for proper operation.
 * <p>
 * This class should be used in favor of <tt>InetAddress</tt> to resolve
 * hostnames on LANs and WANs that support a mixture of NetBIOS/WINS and
 * DNS resolvable hosts.
 */

public class UniAddress implements Address {

    /**
     * Check whether a hostname is actually an ip address
     * 
     * @param hostname
     * @return whether this is an IP address
     */
    public static boolean isDotQuadIP ( String hostname ) {
        if ( Character.isDigit(hostname.charAt(0)) ) {
            int i, len, dots;
            char[] data;

            i = dots = 0; /* quick IP address validation */
            len = hostname.length();
            data = hostname.toCharArray();
            while ( i < len && Character.isDigit(data[ i++ ]) ) {
                if ( i == len && dots == 3 ) {
                    // probably an IP address
                    return true;
                }
                if ( i < len && data[ i ] == '.' ) {
                    dots++;
                    i++;
                }
            }
        }

        return false;
    }

    /**
     * Perform DNS SRV lookup on successively shorter suffixes of name
     * and return successful suffix or throw an UnknownHostException.
     * import javax.naming.*;
     * import javax.naming.directory.*;
     * public static String getDomainByName(String name) throws UnknownHostException {
     * DirContext context;
     * UnknownHostException uhe = null;
     * 
     * try {
     * context = new InitialDirContext();
     * for ( ;; ) {
     * try {
     * Attributes attributes = context.getAttributes(
     * "dns:/_ldap._tcp.dc._msdcs." + name,
     * new String[] { "SRV" }
     * );
     * return name;
     * } catch (NameNotFoundException nnfe) {
     * uhe = new UnknownHostException(nnfe.getMessage());
     * }
     * int dot = name.indexOf('.');
     * if (dot == -1)
     * break;
     * name = name.substring(dot + 1);
     * }
     * } catch (NamingException ne) {
     * if (log.level > 1)
     * ne.printStackTrace(log);
     * }
     * 
     * throw uhe != null ? uhe : new UnknownHostException("invalid name");
     * }
     */

    Object addr;
    String calledName;


    /**
     * Create a <tt>UniAddress</tt> by wrapping an <tt>InetAddress</tt> or
     * <tt>NbtAddress</tt>.
     * 
     * @param addr
     *            wrapped address
     */
    public UniAddress ( Object addr ) {
        if ( addr == null ) {
            throw new IllegalArgumentException();
        }
        this.addr = addr;
    }


    /**
     * Return the IP address of this address as a 32 bit integer.
     */

    @Override
    public int hashCode () {
        return this.addr.hashCode();
    }


    /**
     * Compare two addresses for equality. Two <tt>UniAddress</tt>s are equal
     * if they are both <tt>UniAddress</tt>' and refer to the same IP address.
     */
    @Override
    public boolean equals ( Object obj ) {
        return obj instanceof UniAddress && this.addr.equals( ( (UniAddress) obj ).addr);
    }


    /**
     * Guess first called name to try for session establishment. This
     * method is used exclusively by the <tt>jcifs.smb</tt> package.
     * 
     * @return the guessed name
     */
    @Override
    public String firstCalledName () {
        if ( this.addr instanceof NbtAddress ) {
            return ( (NbtAddress) this.addr ).firstCalledName();
        }

        this.calledName = ( (InetAddress) this.addr ).getHostName();
        if ( isDotQuadIP(this.calledName) ) {
            this.calledName = NbtAddress.SMBSERVER_NAME;
        }
        else {
            int i = this.calledName.indexOf('.');
            if ( i > 1 && i < 15 ) {
                this.calledName = this.calledName.substring(0, i).toUpperCase();
            }
            else if ( this.calledName.length() > 15 ) {
                this.calledName = NbtAddress.SMBSERVER_NAME;
            }
            else {
                this.calledName = this.calledName.toUpperCase();
            }
        }

        return this.calledName;
    }


    /**
     * Guess next called name to try for session establishment. This
     * method is used exclusively by the <tt>jcifs.smb</tt> package.
     * 
     * @param tc
     *            context to use
     * 
     * @return guessed alternate name
     */
    @Override
    public String nextCalledName ( CIFSContext tc ) {
        if ( this.addr instanceof NbtAddress ) {
            return ( (NbtAddress) this.addr ).nextCalledName(tc);
        }
        else if ( this.calledName != NbtAddress.SMBSERVER_NAME ) {
            this.calledName = NbtAddress.SMBSERVER_NAME;
            return this.calledName;
        }
        return null;
    }


    /**
     * Return the underlying <tt>NbtAddress</tt> or <tt>InetAddress</tt>.
     * 
     * @return wrapped address
     */
    public Object getAddress () {
        return this.addr;
    }


    /**
     * Return the hostname of this address such as "MYCOMPUTER".
     * 
     * @return the hostname associated with the address
     */
    @Override
    public String getHostName () {
        if ( this.addr instanceof NbtAddress ) {
            return ( (NbtAddress) this.addr ).getHostName();
        }
        return ( (InetAddress) this.addr ).getHostName();
    }


    /**
     * Return the IP address as text such as "192.168.1.15".
     * 
     * @return the ip address
     */
    @Override
    public String getHostAddress () {
        if ( this.addr instanceof NbtAddress ) {
            return ( (NbtAddress) this.addr ).getHostAddress();
        }
        return ( (InetAddress) this.addr ).getHostAddress();
    }


    /**
     * {@inheritDoc}
     * 
     * @throws UnknownHostException
     *
     * @see jcifs.Address#toInetAddress()
     */
    @Override
    public InetAddress toInetAddress () throws UnknownHostException {
        if ( this.addr instanceof Address ) {
            return ( (Address) this.addr ).toInetAddress();
        }
        else if ( this.addr instanceof InetAddress ) {
            return (InetAddress) this.addr;
        }
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.Address#unwrap(java.lang.Class)
     */
    @SuppressWarnings ( "unchecked" )
    @Override
    public <T extends Address> T unwrap ( Class<T> type ) {
        if ( this.addr instanceof Address ) {
            return ( (Address) this.addr ).unwrap(type);
        }
        else if ( this.getClass().isAssignableFrom(type) ) {
            return (T) this;
        }
        return null;
    }


    /**
     * Return the a text representation of this address such as
     * <tt>MYCOMPUTER/192.168.1.15</tt>.
     */
    @Override
    public String toString () {
        return this.addr.toString();
    }
}
