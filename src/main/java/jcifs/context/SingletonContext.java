/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs.context;


import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.RuntimeCIFSException;
import jcifs.config.PropertyConfiguration;


/**
 * Global singleton context
 * 
 * @author mbechler
 *
 */
public class SingletonContext extends BaseContext implements CIFSContext {

    private static final Logger log = LoggerFactory.getLogger(SingletonContext.class);
    private static SingletonContext INSTANCE;


    /**
     * Initialize singleton context using custom properties
     * 
     * This method can only be called once.
     * 
     * @param props
     * @throws CIFSException
     */
    public static synchronized final void init ( Properties props ) throws CIFSException {
        if ( INSTANCE != null ) {
            throw new CIFSException("Singleton context is already initialized");
        }
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
        if ( props != null ) {
            p.putAll(props);
        }
        INSTANCE = new SingletonContext(p);
    }


    /**
     * Get singleton context
     * 
     * The singleton context will use system properties for configuration as well as values specified in a file
     * specified through this <tt>jcifs.properties</tt> system property.
     * 
     * @return a global context, initialized on first call
     */
    public static synchronized final SingletonContext getInstance () {
        if ( INSTANCE == null ) {
            try {
                log.debug("Initializing singleton context");
                init(null);
            }
            catch ( CIFSException e ) {
                log.error("Failed to create singleton JCIFS context", e);
            }
        }
        return INSTANCE;
    }


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
     * 
     */
    public static void registerSmbURLHandler () {
        String pkgs;
        float ver = Float.parseFloat(Runtime.class.getPackage().getSpecificationVersion());
        String vendor = System.getProperty("java.vendor.url");
        if ( ! ( vendor != null && vendor.startsWith("http://www.android.com") ) && ver < 1.7f ) {
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


    /**
     * 
     */
    private SingletonContext ( Properties p ) throws CIFSException {
        super(new PropertyConfiguration(p));
    }

}
