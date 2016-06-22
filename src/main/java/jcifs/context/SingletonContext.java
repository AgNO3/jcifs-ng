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
