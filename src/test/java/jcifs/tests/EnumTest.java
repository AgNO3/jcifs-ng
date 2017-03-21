/*tr
 * © 2017 AgNO3 Gmbh & Co. KG
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
package jcifs.tests;


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class EnumTest extends BaseCIFSTest {

    private static final Logger log = LoggerFactory.getLogger(EnumTest.class);


    /**
     * @param name
     * @param properties
     */
    public EnumTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("noUnicode", "forceUnicode", "noNTStatus", "noNTSmbs");
    }


    @Test
    public void testShareEnum () throws MalformedURLException, SmbException {
        try ( SmbFile smbFile = new SmbFile("smb://" + getTestServer(), getContext()) ) {
            String[] list = smbFile.list();
            assertNotNull(list);
            assertTrue("No share found", list.length > 0);
            log.debug(Arrays.toString(list));
        }
    }


    @Test
    public void testDomainShareEnum () throws MalformedURLException, SmbException {
        try ( SmbFile smbFile = new SmbFile("smb://" + getTestDomain(), getContext()) ) {
            String[] list = smbFile.list();
            assertNotNull(list);
            assertTrue("No share found", list.length > 0);
            log.debug(Arrays.toString(list));
        }
    }


    @Test
    public void testDFSShareEnum () throws SmbException, MalformedURLException {
        try ( SmbFile smbFile = new SmbFile(getDFSRootURL(), withTestNTLMCredentials(getContext())) ) {
            String[] list = smbFile.list();
            assertNotNull(list);
            assertTrue("No share found", list.length > 0);
            log.debug(Arrays.toString(list));
        }
    }
}
