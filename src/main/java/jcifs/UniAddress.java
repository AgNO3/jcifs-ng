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

package jcifs;


import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import jcifs.netbios.NbtAddress;


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

public class UniAddress {

    static class Sem {

        Sem ( int count ) {
            this.count = count;
        }

        int count;
    }

    static class QueryThread extends Thread {

        private Sem sem;
        private String host, scope;
        private int type;
        private NbtAddress ans = null;
        private InetAddress svr;
        private UnknownHostException uhe;
        private CIFSContext tc;


        QueryThread ( Sem sem, String host, int type, String scope, InetAddress svr, CIFSContext tc ) {
            super("JCIFS-QueryThread: " + host);
            this.sem = sem;
            this.host = host;
            this.type = type;
            this.scope = scope;
            this.svr = svr;
            this.tc = tc;
        }


        @Override
        public void run () {
            try {
                this.ans = NbtAddress.getByName(this.host, this.type, this.scope, this.svr, this.tc);
            }
            catch ( UnknownHostException ex ) {
                this.uhe = ex;
            }
            catch ( Exception ex ) {
                this.uhe = new UnknownHostException(ex.getMessage());
            }
            finally {
                synchronized ( this.sem ) {
                    this.sem.count--;
                    this.sem.notify();
                }
            }
        }


        /**
         * @return the ans
         */
        public NbtAddress getAnswer () {
            return this.ans;
        }


        /**
         * @return the uhe
         */
        public UnknownHostException getException () {
            return this.uhe;
        }

    }


    static NbtAddress lookupServerOrWorkgroup ( String name, InetAddress svr, CIFSContext tc ) throws UnknownHostException {
        Sem sem = new Sem(2);
        int type = NbtAddress.isWINS(tc, svr) ? 0x1b : 0x1d;

        QueryThread q1x = new QueryThread(sem, name, type, null, svr, tc);
        QueryThread q20 = new QueryThread(sem, name, 0x20, null, svr, tc);
        q1x.setDaemon(true);
        q20.setDaemon(true);
        try {
            synchronized ( sem ) {
                q1x.start();
                q20.start();

                while ( sem.count > 0 && q1x.getAnswer() == null && q20.getAnswer() == null ) {
                    sem.wait();
                }
            }
        }
        catch ( InterruptedException ie ) {
            throw new UnknownHostException(name);
        }
        waitForQueryThreads(q1x, q20);
        if ( q1x.getAnswer() != null ) {
            return q1x.getAnswer();
        }
        else if ( q20.getAnswer() != null ) {
            return q20.getAnswer();
        }
        else {
            throw q1x.getException();
        }
    }


    private static void waitForQueryThreads ( QueryThread q1x, QueryThread q20 ) {
        interruptThreadSafely(q1x);
        joinThread(q1x);
        interruptThreadSafely(q20);
        joinThread(q20);
    }


    private static void interruptThreadSafely ( QueryThread thread ) {
        try {
            thread.interrupt();
        }
        catch ( SecurityException e ) {
            e.printStackTrace();
        }
    }


    private static void joinThread ( Thread thread ) {
        try {
            thread.join();
        }
        catch ( InterruptedException e ) {
            e.printStackTrace();
        }
    }


    /**
     * Determines the address of a host given it's host name. The name can be a
     * machine name like "jcifs.samba.org", or an IP address like "192.168.1.15".
     *
     * @param hostname
     *            NetBIOS or DNS hostname to resolve
     * @throws java.net.UnknownHostException
     *             if there is an error resolving the name
     */

    public static UniAddress getByName ( String hostname, CIFSContext tc ) throws UnknownHostException {
        return getByName(hostname, false, tc);
    }


    static boolean isDotQuadIP ( String hostname ) {
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


    static boolean isAllDigits ( String hostname ) {
        for ( int i = 0; i < hostname.length(); i++ ) {
            if ( Character.isDigit(hostname.charAt(i)) == false ) {
                return false;
            }
        }
        return true;
    }


    /**
     * Lookup <tt>hostname</tt> and return it's <tt>UniAddress</tt>. If the
     * <tt>possibleNTDomainOrWorkgroup</tt> parameter is <tt>true</tt> an
     * addtional name query will be performed to locate a master browser.
     */

    public static UniAddress getByName ( String hostname, boolean possibleNTDomainOrWorkgroup, CIFSContext tc ) throws UnknownHostException {
        UniAddress[] addrs = UniAddress.getAllByName(hostname, possibleNTDomainOrWorkgroup, tc);
        return addrs[ 0 ];
    }


    public static UniAddress[] getAllByName ( String hostname, boolean possibleNTDomainOrWorkgroup, CIFSContext tc ) throws UnknownHostException {
        Object addr;
        if ( hostname == null || hostname.length() == 0 ) {
            throw new UnknownHostException();
        }

        if ( isDotQuadIP(hostname) ) {
            UniAddress[] addrs = new UniAddress[1];
            addrs[ 0 ] = new UniAddress(NbtAddress.getByName(hostname, tc));
            return addrs;
        }

        for ( ResolverType resolver : tc.getConfig().getResolveOrder() ) {
            try {
                switch ( resolver ) {
                case RESOLVER_LMHOSTS:
                    if ( ( addr = tc.getNameServiceClient().getLmhosts().getByName(hostname, tc) ) == null ) {
                        continue;
                    }
                    break;
                case RESOLVER_WINS:
                    if ( hostname == NbtAddress.MASTER_BROWSER_NAME || hostname.length() > 15 ) {
                        // invalid netbios name
                        continue;
                    }
                    if ( possibleNTDomainOrWorkgroup ) {
                        addr = lookupServerOrWorkgroup(hostname, NbtAddress.getWINSAddress(tc), tc);
                    }
                    else {
                        addr = NbtAddress.getByName(hostname, 0x20, null, NbtAddress.getWINSAddress(tc), tc);
                    }
                    break;
                case RESOLVER_BCAST:
                    if ( hostname.length() > 15 ) {
                        // invalid netbios name
                        continue;
                    }
                    if ( possibleNTDomainOrWorkgroup ) {
                        addr = lookupServerOrWorkgroup(hostname, tc.getConfig().getBroadcastAddress(), tc);
                    }
                    else {
                        addr = NbtAddress.getByName(hostname, 0x20, null, tc.getConfig().getBroadcastAddress(), tc);
                    }
                    break;
                case RESOLVER_DNS:
                    if ( isAllDigits(hostname) ) {
                        throw new UnknownHostException(hostname);
                    }
                    InetAddress[] iaddrs = InetAddress.getAllByName(hostname);
                    UniAddress[] addrs = new UniAddress[iaddrs.length];
                    for ( int ii = 0; ii < iaddrs.length; ii++ ) {
                        addrs[ ii ] = new UniAddress(iaddrs[ ii ]);
                    }
                    return addrs; // Success
                default:
                    throw new UnknownHostException(hostname);
                }
                UniAddress[] addrs = new UniAddress[1];
                addrs[ 0 ] = new UniAddress(addr);
                return addrs; // Success
            }
            catch ( IOException ioe ) {
                // Failure
            }
        }
        throw new UnknownHostException(hostname);
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
    /*
     * public boolean equals( Object obj ) {
     * return obj instanceof UniAddress && addr.hashCode() == obj.hashCode();
     * }
     */


    /**
     * Guess first called name to try for session establishment. This
     * method is used exclusively by the <tt>jcifs.smb</tt> package.
     */

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
     */

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
     */

    public Object getAddress () {
        return this.addr;
    }


    /**
     * Return the hostname of this address such as "MYCOMPUTER".
     */

    public String getHostName () {
        if ( this.addr instanceof NbtAddress ) {
            return ( (NbtAddress) this.addr ).getHostName();
        }
        return ( (InetAddress) this.addr ).getHostName();
    }


    /**
     * Return the IP address as text such as "192.168.1.15".
     */

    public String getHostAddress () {
        if ( this.addr instanceof NbtAddress ) {
            return ( (NbtAddress) this.addr ).getHostAddress();
        }
        return ( (InetAddress) this.addr ).getHostAddress();
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
