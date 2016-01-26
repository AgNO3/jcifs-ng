/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.01.2016 by mbechler
 */
package jcifs.context;


import org.apache.log4j.Logger;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.config.PropertyConfiguration;


/**
 * @author mbechler
 *
 */
public class SingletonContext extends BaseContext implements CIFSContext {

    private static final Logger log = Logger.getLogger(SingletonContext.class);
    private static SingletonContext INSTANCE;


    public static final SingletonContext getInstance () {
        if ( INSTANCE == null ) {
            try {
                log.debug("Initializing singleton context");
                INSTANCE = new SingletonContext();
            }
            catch ( CIFSException e ) {
                log.error("Failed to create singleton JCIFS context", e);
            }
        }

        return INSTANCE;
    }


    /**
     * 
     */
    private SingletonContext () throws CIFSException {
        super(new PropertyConfiguration(System.getProperties()));
    }

}
