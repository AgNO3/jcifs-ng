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


/**
 * @author mbechler
 *
 */
public final class TestProperties {

    /**
     * 
     */
    private TestProperties () {}

    static final String TEST_SHARE_URL_MAIN = "test.share.main.url";
    static final String TEST_SHARE_URL_DFSROOT = "test.share.dfsroot.url";

    static final String TEST_SHARE_MAIN = "test.share.main";
    static final String TEST_SHARE_GUEST = "test.share.guest";

    static final String TEST_USER_NAME = "test.user.name";
    static final String TEST_USER_PASSWORD = "test.user.password";
    static final String TEST_USER_DOMAIN = "test.user.domain";
    static final String TEST_USER_DOMAIN_SHORT = "test.user.sdomain";
    static final String TEST_SERVER = "test.server";

    static final String TEST_DOMAIN = "test.domain";
    static final String TEST_DOMAIN_SHORT = "test.domain.netbios";
    static final String TEST_DOMAIN_SID = "test.domain.sid";
    static final String TEST_DOMAIN_DC = "test.domain.dc";
    static final String TEST_USER_SID = "test.user.sid";

    static final String TEST_GROUP_SID = "test.group.sid";
    static final String TEST_GROUP_NAME = "test.group.name";

    static final String TEST_CONFIG_DIR = "test.config.dir";

    static final String TEST_MUTATIONS = "test.mutations";

    static final String EXCLUDE_TEST_MUTATIONS = "test.mutations.exclude";

    static final Object TEST_FIFO_PIPE = "test.pipe.fifo";
    static final Object TEST_TRANSACT_PIPE = "test.pipe.transact";
    static final Object TEST_CALL_PIPE = "test.pipe.call";

}
