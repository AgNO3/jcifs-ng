/*
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


import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Map;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jcifs.CIFSContext;
import jcifs.SmbConstants;
import jcifs.SmbSession;
import jcifs.internal.smb1.com.SmbComClose;
import jcifs.internal.smb1.com.SmbComNTCreateAndX;
import jcifs.internal.smb1.com.SmbComNTCreateAndXResponse;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.smb2.create.Smb2CloseRequest;
import jcifs.internal.smb2.create.Smb2CreateRequest;
import jcifs.smb.SmbSessionInternal;
import jcifs.smb.SmbTransportInternal;
import jcifs.smb.SmbTreeInternal;
import jcifs.util.transport.RequestTimeoutException;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( "javadoc" )
@RunWith ( Parameterized.class )
public class OplockTests extends BaseCIFSTest {

    /**
     * @param name
     * @param properties
     */
    public OplockTests ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "smb2", "smb30", "smb31");
    }


    @Test
    public void testOpenOplocked () throws UnknownHostException, IOException {
        CIFSContext c = getContext();
        c = withTestNTLMCredentials(c);
        try ( SmbTransportInternal trans = c.getTransportPool().getSmbTransport(c, getTestServer(), 0, false, true)
                .unwrap(SmbTransportInternal.class);
              SmbSession sess = trans.unwrap(SmbTransportInternal.class).getSmbSession(c, getTestServer(), null);
              SmbTreeInternal tree = sess.unwrap(SmbSessionInternal.class).getSmbTree(getTestShare(), null).unwrap(SmbTreeInternal.class) ) {

            if ( trans.isSMB2() ) {
                Smb2CreateRequest create = new Smb2CreateRequest(sess.getConfig(), "\\foocc");
                create.setCreateDisposition(Smb2CreateRequest.FILE_OPEN_IF);
                create.setRequestedOplockLevel(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);

                tree.send(create);

                Smb2CreateRequest create2 = new Smb2CreateRequest(sess.getConfig(), "\\foocc");
                create2.setOverrideTimeout(1000);
                create2.setCreateDisposition(Smb2CreateRequest.FILE_OPEN_IF);
                create2.setRequestedOplockLevel(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);

                create2.chain(new Smb2CloseRequest(sess.getConfig(), Smb2Constants.UNSPECIFIED_FILEID));

                try {
                    tree.send(create2);
                }
                catch ( Exception e ) {
                    // timeout is expected for now as we do not ack the break
                    if ( ! ( e.getCause() instanceof RequestTimeoutException ) ) {
                        throw e;
                    }
                }
            }
            else if ( trans.hasCapability(SmbConstants.CAP_NT_SMBS) ) {
                int flags = SmbConstants.O_CREAT;
                int sharing = SmbConstants.FILE_SHARE_DELETE | SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE;
                int access = SmbConstants.FILE_READ_DATA | SmbConstants.FILE_READ_ATTRIBUTES | SmbConstants.FILE_WRITE_ATTRIBUTES
                        | SmbConstants.FILE_WRITE_DATA;
                int attrs = 0;
                int options = 0;
                String uncPath = "foo-oplock";

                SmbComNTCreateAndXResponse resp = null;
                SmbComNTCreateAndX req = new SmbComNTCreateAndX(sess.getConfig(), uncPath, flags, access, sharing, attrs, options, null);
                req.addFlags0(0x2); // REQUEST_OPLOCK
                try {
                    resp = tree.send(req);
                    SmbComNTCreateAndXResponse resp2 = null;
                    SmbComNTCreateAndX req2 = new SmbComNTCreateAndX(sess.getConfig(), uncPath, flags, access, sharing, attrs, options, null);
                    req2.addFlags0(0x2); // REQUEST_OPLOCK
                    req2.setOverrideTimeout(1000);

                    try {
                        resp2 = tree.send(req2);
                    }
                    catch ( Exception e ) {
                        // timeout is expected for now as we do not ack the break
                        if ( ! ( e.getCause() instanceof RequestTimeoutException ) ) {
                            throw e;
                        }
                    }
                    finally {
                        if ( resp2 != null && !trans.isDisconnected() ) {
                            tree.send(new SmbComClose(sess.getConfig(), resp2.getFid(), 0L));
                        }
                    }
                }
                finally {
                    if ( resp != null && !trans.isDisconnected() ) {
                        tree.send(new SmbComClose(sess.getConfig(), resp.getFid(), 0L));
                    }
                }
            }
            else {
                Assume.assumeTrue(false);
            }
        }
        finally {
            c.close();
        }
    }
}
