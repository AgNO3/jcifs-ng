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


import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

import jcifs.context.SingletonContext;


/**
 * This class uses a static {@link java.util.Properties} to act
 * as a cental repository for all jCIFS configuration properties. It cannot be
 * instantiated. Similar to <code>System</code> properties the namespace
 * is global therefore property names should be unique. Before use,
 * the <code>load</code> method should be called with the name of a
 * <code>Properties</code> file (or <code>null</code> indicating no
 * file) to initialize the <code>Config</code>. The <code>System</code>
 * properties will then populate the <code>Config</code> as well potentially
 * overwriting properties from the file. Thus properties provided on the
 * commandline with the <code>-Dproperty.name=value</code> VM parameter
 * will override properties from the configuration file.
 * <p>
 * There are several ways to set jCIFS properties. See
 * the <a href="../overview-summary.html#scp">overview page of the API
 * documentation</a> for details.
 */

public class Config {

    /**
     * The static <code>Properties</code>.
     */

    private Properties prp = new Properties();
    private static final Logger log = Logger.getLogger(Config.class);


    /**
     * This static method registers the SMB URL protocol handler which is
     * required to use SMB URLs with the <tt>java.net.URL</tt> class. If this
     * method is not called before attempting to create an SMB URL with the
     * URL class the following exception will occur:
     * <blockquote>
     * 
     * <pre>
     * Exception MalformedURLException: unknown protocol: smb
     *     at java.net.URL.<init>(URL.java:480)
     *     at java.net.URL.<init>(URL.java:376)
     *     at java.net.URL.<init>(URL.java:330)
     *     at jcifs.smb.SmbFile.<init>(SmbFile.java:355)
     *     ...
     * </pre>
     * 
     * <blockquote>
     */

    public static void registerSmbURLHandler () {
        String pkgs;
        float ver = Float.parseFloat(Runtime.class.getPackage().getSpecificationVersion());
        if ( ver < 1.7f ) {
            throw new RuntimeCIFSException("jcifs-ng requires Java 1.7 or above. You are running " + ver);
        }

        SingletonContext.getInstance();
        pkgs = System.getProperty("java.protocol.handler.pkgs");
        if ( pkgs == null ) {
            System.setProperty("java.protocol.handler.pkgs", "jcifs");
        }
        else if ( pkgs.indexOf("jcifs") == -1 ) {
            pkgs += "|jcifs";
            System.setProperty("java.protocol.handler.pkgs", pkgs);
        }
    }


    // supress javadoc constructor summary by removing 'protected'
    public Config () throws CIFSException {
        Properties p = new Properties();
        try {
            String filename = System.getProperty("jcifs.properties");
            if ( filename != null && filename.length() > 1 ) {

                try ( FileInputStream in = new FileInputStream(filename) ) {
                    p.load(in);
                }
            }

        }
        catch ( IOException ioe ) {
            log.error("Failed to load config", ioe); //$NON-NLS-1$
        }

        p.putAll(System.getProperties());
        init(p);
    }


    public Config ( Properties p ) throws CIFSException {
        init(p);
    }


    /**
     * @param p
     */
    private final void init ( Properties p ) throws CIFSException {
        this.prp = p;
        try {
            "".getBytes(SmbConstants.DEFAULT_OEM_ENCODING);
        }
        catch ( UnsupportedEncodingException uee ) {
            throw new CIFSException(
                "The default OEM encoding " + SmbConstants.DEFAULT_OEM_ENCODING + " does not appear to be supported by this JRE.");
        }
    }


    /**
     * Set the default properties of the static Properties used by <tt>Config</tt>. This permits
     * a different Properties object/file to be used as the source of properties for
     * use by the jCIFS library. The Properties must be set <i>before jCIFS
     * classes are accessed</i> as most jCIFS classes load properties statically once.
     * Using this method will also override properties loaded
     * using the <tt>-Djcifs.properties=</tt> commandline parameter.
     */

    public void setProperties ( Properties prp ) {
        prp = new Properties(prp);
        try {
            prp.putAll(System.getProperties());
        }
        catch ( SecurityException se ) {
            log.error("SecurityException: jcifs will ignore System properties");
        }
    }


    /**
     * @return the prp
     */
    public Properties getProperties () {
        return this.prp;
    }


    /**
     * Add a property.
     */

    public Object setProperty ( String key, String value ) {
        return this.prp.setProperty(key, value);
    }


    /**
     * Retrieve a property as an <code>Object</code>.
     */

    public Object get ( String key ) {
        return this.prp.get(key);
    }


    /**
     * Retrieve a <code>String</code>. If the key cannot be found,
     * the provided <code>def</code> default parameter will be returned.
     */

    public String getProperty ( String key, String def ) {
        return this.prp.getProperty(key, def);
    }


    /**
     * Retrieve a <code>String</code>. If the property is not found, <code>null</code> is returned.
     */

    public String getProperty ( String key ) {
        return this.prp.getProperty(key);
    }


    /**
     * Retrieve an <code>int</code>. If the key does not exist or
     * cannot be converted to an <code>int</code>, the provided default
     * argument will be returned.
     */

    public int getInt ( String key, int def ) {
        String s = this.prp.getProperty(key);
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

    public int getInt ( String key ) {
        String s = this.prp.getProperty(key);
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

    public long getLong ( String key, long def ) {
        String s = this.prp.getProperty(key);
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

    public InetAddress getInetAddress ( String key, InetAddress def ) {
        String addr = this.prp.getProperty(key);
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


    public InetAddress getLocalHost () {
        String addr = this.prp.getProperty("jcifs.smb.client.laddr");

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

    public boolean getBoolean ( String key, boolean def ) {
        String b = getProperty(key);
        if ( b != null ) {
            def = b.toLowerCase().equals("true");
        }
        return def;
    }


    /**
     * Retrieve an array of <tt>InetAddress</tt> created from a property
     * value containting a <tt>delim</tt> separated list of hostnames and/or
     * ipaddresses.
     */

    public InetAddress[] getInetAddressArray ( String key, String delim, InetAddress[] def ) {
        String p = getProperty(key);
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
