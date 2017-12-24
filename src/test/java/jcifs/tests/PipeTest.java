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


import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jcifs.dcerpc.DcerpcException;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.msrpc.LsaPolicyHandle;
import jcifs.dcerpc.msrpc.MsrpcLookupSids;
import jcifs.dcerpc.msrpc.MsrpcShareEnum;
import jcifs.smb.SID;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class PipeTest extends BaseCIFSTest {

    /**
     * @param name
     * @param properties
     */
    public PipeTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "noUnicode", "forceUnicode", "noNTStatus", "noNTSmbs", "smb2", "smb30", "smb31");
    }


    @Test
    public void testSRVS () throws DcerpcException, IOException {
        try ( DcerpcHandle handle = DcerpcHandle
                .getHandle("ncacn_np:" + getTestServer() + "[\\PIPE\\srvsvc]", withTestNTLMCredentials(getContext())) ) {
            MsrpcShareEnum rpc = new MsrpcShareEnum(handle.getServerWithDfs());
            handle.sendrecv(rpc);
            assertEquals(0, rpc.retval);
        }
    }


    @Test
    public void exclusiveConnection () throws IOException {
        try ( DcerpcHandle handle = DcerpcHandle
                .getHandle("ncacn_np:" + getTestServer() + "[\\PIPE\\srvsvc]", withTestNTLMCredentials(getContext()), true) ) {
            MsrpcShareEnum rpc = new MsrpcShareEnum(handle.getServerWithDfs());
            handle.sendrecv(rpc);
            assertEquals(0, rpc.retval);
        }
    }


    @Test
    public void testLSA () throws DcerpcException, IOException {
        try ( DcerpcHandle handle = DcerpcHandle
                .getHandle("ncacn_np:" + getTestServer() + "[\\PIPE\\lsarpc]", withTestNTLMCredentials(getContext())) ) {
            String server = handle.getServerWithDfs();
            int dot = server.indexOf('.');
            if ( dot > 0 && Character.isDigit(server.charAt(0)) == false )
                server = server.substring(0, dot);

            try ( LsaPolicyHandle policyHandle = new LsaPolicyHandle(handle, "\\\\" + server, 0x00000800) ) {
                MsrpcLookupSids rpc = new MsrpcLookupSids(policyHandle, new SID[] {
                    SID.EVERYONE
                });
                handle.sendrecv(rpc);

                assertEquals(0, rpc.retval);
            }
        }
    }

}
