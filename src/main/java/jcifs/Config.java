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


import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;
import java.util.StringTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.context.SingletonContext;


/**
 * This class now contains only utilities for config parsing.
 * 
 * We strongly suggest that you create an explicit {@link jcifs.context.CIFSContextWrapper}
 * with your desired config. It's base implementation {@link jcifs.context.BaseContext}
 * should be sufficient for most needs.
 * 
 * If you want to retain the classic singleton behavior you can use
 * {@link jcifs.context.SingletonContext#getInstance()}
 * witch is initialized using system properties.
 * 
 */
@SuppressWarnings ( "javadoc" )
public class Config {

    private static final Logger log = LoggerFactory.getLogger(Config.class);


    /**
     * This static method registers the SMB URL protocol handler which is
     * required to use SMB URLs with the <tt>java.net.URL</tt> class. If this
     * method is not called before attempting to create an SMB URL with the
     * URL class the following exception will occur:
     * <blockquote>
     * 
     * <pre>
     * Exception MalformedURLException: unknown protocol: smb
     *     at java.net.URL.&lt;init&gt;(URL.java:480)
     *     at java.net.URL.&lt;init&gt;(URL.java:376)
     *     at java.net.URL.&lt;init&gt;(URL.java:330)
     *     at jcifs.smb.SmbFile.&lt;init&gt;(SmbFile.java:355)
     *     ...
     * </pre>
     * 
     * <blockquote>
     */
    public static void registerSmbURLHandler () {
        SingletonContext.registerSmbURLHandler();
    }


    /**
     * Retrieve an <code>int</code>. If the key does not exist or
     * cannot be converted to an <code>int</code>, the provided default
     * argument will be returned.
     */
    public static int getInt ( Properties props, String key, int def ) {
        String s = props.getProperty(key);
        if ( s != null ) {
            try {
                def = Integer.parseInt(s);
            }
            catch ( NumberFormatException nfe ) {
                log.error("Not a number", nfe);
            }
        }
        return def;
    }


    /**
     * Retrieve an <code>int</code>. If the property is not found, <code>-1</code> is returned.
     */
    public static int getInt ( Properties props, String key ) {
        String s = props.getProperty(key);
        int result = -1;
        if ( s != null ) {
            try {
                result = Integer.parseInt(s);
            }
            catch ( NumberFormatException nfe ) {
                log.error("Not a number", nfe);
            }
        }
        return result;
    }


    /**
     * Retrieve a <code>long</code>. If the key does not exist or
     * cannot be converted to a <code>long</code>, the provided default
     * argument will be returned.
     */
    public static long getLong ( Properties props, String key, long def ) {
        String s = props.getProperty(key);
        if ( s != null ) {
            try {
                def = Long.parseLong(s);
            }
            catch ( NumberFormatException nfe ) {
                log.error("Not a number", nfe);
            }
        }
        return def;
    }


    /**
     * Retrieve an <code>InetAddress</code>. If the address is not
     * an IP address and cannot be resolved <code>null</code> will
     * be returned.
     */
    public static InetAddress getInetAddress ( Properties props, String key, InetAddress def ) {
        String addr = props.getProperty(key);
        if ( addr != null ) {
            try {
                def = InetAddress.getByName(addr);
            }
            catch ( UnknownHostException uhe ) {
                log.error("Unknown host " + addr, uhe);
            }
        }
        return def;
    }


    public static InetAddress getLocalHost ( Properties props ) {
        String addr = props.getProperty("jcifs.smb.client.laddr");

        if ( addr != null ) {
            try {
                return InetAddress.getByName(addr);
            }
            catch ( UnknownHostException uhe ) {
                log.error("Ignoring jcifs.smb.client.laddr address: " + addr, uhe);
            }
        }

        return null;
    }


    /**
     * Retrieve a boolean value. If the property is not found, the value of <code>def</code> is returned.
     */
    public static boolean getBoolean ( Properties props, String key, boolean def ) {
        String b = props.getProperty(key);
        if ( b != null ) {
            def = b.toLowerCase().equals("true");
        }
        return def;
    }


    /**
     * Retrieve an array of <tt>InetAddress</tt> created from a property
     * value containing a <tt>delim</tt> separated list of host names and/or
     * ip addresses.
     */
    public static InetAddress[] getInetAddressArray ( Properties props, String key, String delim, InetAddress[] def ) {
        String p = props.getProperty(key);
        if ( p != null ) {
            StringTokenizer tok = new StringTokenizer(p, delim);
            int len = tok.countTokens();
            InetAddress[] arr = new InetAddress[len];
            for ( int i = 0; i < len; i++ ) {
                String addr = tok.nextToken();
                try {
                    arr[ i ] = InetAddress.getByName(addr);
                }
                catch ( UnknownHostException uhe ) {
                    log.error("Unknown host " + addr, uhe);
                    return def;
                }
            }
            return arr;
        }
        return def;
    }

}
