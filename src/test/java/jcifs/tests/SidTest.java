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
package jcifs.tests;


import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jcifs.smb.SID;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class SidTest extends BaseCIFSTest {

    /**
     * @param name
     * @param properties
     */
    public SidTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "smb2", "smb30");
    }


    @Test
    public void resolveUserSID () throws IOException {
        String sid = getRequiredProperty(TestProperties.TEST_USER_SID);
        SID s = new SID(sid);
        s.resolve(getRequiredProperty(TestProperties.TEST_DOMAIN_DC), withTestNTLMCredentials(getContext()));
        assertEquals(getRequiredProperty(TestProperties.TEST_USER_DOMAIN_SHORT), s.getDomainName());
        assertEquals(getTestUser(), s.getAccountName());
        assertEquals(jcifs.SID.SID_TYPE_USER, s.getType());
    }


    @Test
    public void resolveGroupSID () throws IOException {
        String sid = getRequiredProperty(TestProperties.TEST_GROUP_SID);
        SID s = new SID(sid);
        s.resolve(getRequiredProperty(TestProperties.TEST_DOMAIN_DC), withTestNTLMCredentials(getContext()));
        assertEquals(getRequiredProperty(TestProperties.TEST_USER_DOMAIN_SHORT), s.getDomainName());
        assertEquals(getRequiredProperty(TestProperties.TEST_GROUP_NAME), s.getAccountName());
        assertEquals(jcifs.SID.SID_TYPE_DOM_GRP, s.getType());
    }


    @Test
    public void resolveWellKnownUsers () throws IOException {
        SID domsid = new SID(getRequiredProperty(TestProperties.TEST_DOMAIN_SID));
        int rids[] = new int[] {
            500, 501
        };
        for ( int rid : rids ) {
            SID sid = new SID(domsid, rid);
            sid.resolve(getRequiredProperty(TestProperties.TEST_DOMAIN_DC), withTestNTLMCredentials(getContext()));
            assertEquals(getRequiredProperty(TestProperties.TEST_DOMAIN_SHORT), sid.getDomainName());
            assertEquals(jcifs.SID.SID_TYPE_USER, sid.getType());
        }
    }


    @Test
    public void resolveWellKnownGroups () throws IOException {
        SID domsid = new SID(getRequiredProperty(TestProperties.TEST_DOMAIN_SID));
        int rids[] = new int[] {
            512, 513, 514
        };
        for ( int rid : rids ) {
            SID sid = new SID(domsid, rid);
            sid.resolve(getRequiredProperty(TestProperties.TEST_DOMAIN_DC), withTestNTLMCredentials(getContext()));
            assertEquals(getRequiredProperty(TestProperties.TEST_DOMAIN_SHORT), sid.getDomainName());
            assertEquals(jcifs.SID.SID_TYPE_DOM_GRP, sid.getType());
        }
    }


    @Test
    public void resolveLazyType () throws IOException {
        String sid = getRequiredProperty(TestProperties.TEST_USER_SID);
        SID s = new SID(sid);
        s.initContext(getRequiredProperty(TestProperties.TEST_DOMAIN_DC), withTestNTLMCredentials(getContext()));
        assertEquals(jcifs.SID.SID_TYPE_USER, s.getType());
    }

}
