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
package jcifs.smb;


import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;


/**
 * @author mbechler
 *
 */
class StaticJAASConfiguration extends Configuration {

    private Map<String, ?> options;


    /**
     * Initialize a static JAAS configuration with default settings
     */
    public StaticJAASConfiguration () {
        this.options = new HashMap<>();
    }


    /**
     * Initialize a static JAAS configuration with custom settings
     * 
     * @param options
     */
    public StaticJAASConfiguration ( Map<String, ?> options ) {
        this.options = options;
    }


    /**
     * {@inheritDoc}
     *
     * @see javax.security.auth.login.Configuration#getAppConfigurationEntry(java.lang.String)
     */
    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry ( String name ) {
        return new AppConfigurationEntry[] {
            new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", LoginModuleControlFlag.REQUIRED, this.options)
        };
    }

}
