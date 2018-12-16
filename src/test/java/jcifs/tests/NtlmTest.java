/*
 * © 2018 AgNO3 Gmbh & Co. KG
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


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import jcifs.CIFSContext;
import jcifs.context.SingletonContext;
import jcifs.ntlmssp.NtlmFlags;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( "javadoc" )
public class NtlmTest {

    private CIFSContext context;


    @Before
    public void setUp () {
        this.context = SingletonContext.getInstance();
    }


    @Test
    public void testParsingType1 () throws IOException {
        int flags = 0x80000000;
        String suppliedDomain = "TESTDOM";
        String suppliedWorkstation = "TESTWS";
        Type1Message t1 = new Type1Message(this.context, flags, suppliedDomain, suppliedWorkstation);

        int origFlags = t1.getFlags();

        Type1Message parsed = new Type1Message(t1.toByteArray());

        assertEquals(origFlags, parsed.getFlags());

        if ( parsed.getFlag(NtlmFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED) ) {
            assertEquals(suppliedDomain, parsed.getSuppliedDomain());
        }

        if ( parsed.getFlag(NtlmFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED) ) {
            assertEquals(suppliedWorkstation, parsed.getSuppliedWorkstation());
        }
    }


    @Test
    public void testParsingType2Target () throws IOException {
        int flags = NtlmFlags.NTLMSSP_REQUEST_TARGET;
        String target = "TARGET";
        byte[] challenge = new byte[] {
            0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8
        };

        Type2Message t2 = new Type2Message(this.context, flags, challenge, target);
        Type2Message parsed = new Type2Message(t2.toByteArray());
        assertArrayEquals(challenge, parsed.getChallenge());
        assertEquals(target, parsed.getTarget());
    }


    @Test
    public void testParsingType2NoTarget () throws IOException {
        int flags = 0;
        byte[] challenge = new byte[] {
            0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8
        };

        Type2Message t2 = new Type2Message(this.context, flags, challenge, null);
        Type2Message parsed = new Type2Message(t2.toByteArray());
        assertArrayEquals(challenge, parsed.getChallenge());
        assertNull(parsed.getTarget());
        assertNull(parsed.getTargetInformation());
    }


    @Test
    public void testParsingType2TargetInformation () throws IOException {
        int flags = 0;
        byte[] challenge = new byte[] {
            0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8
        };

        byte[] ti = new byte[] {
            0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8
        };

        Type2Message t2 = new Type2Message(this.context, flags, challenge, null);
        t2.setTargetInformation(ti);

        Type2Message parsed = new Type2Message(t2.toByteArray());
        assertArrayEquals(challenge, parsed.getChallenge());
        assertNull(parsed.getTarget());
        assertArrayEquals(ti, parsed.getTargetInformation());
    }


    @Test
    public void testParsingType3 () throws IOException {

        int flags = 0;
        byte[] lmResponse = new byte[] {
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
        };
        byte[] ntResponse = new byte[] {
            0xF, 0xE, 0xD, 0xC, 0xB, 0xA, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0
        };
        String domain = "TESTDOM";
        String user = "TESTUSER";
        String workstation = "TESTWS";
        Type3Message t3 = new Type3Message(flags, lmResponse, ntResponse, domain, user, workstation);

        Type3Message parsed = new Type3Message(t3.toByteArray());

        assertEquals(domain, parsed.getDomain());
        assertEquals(user, parsed.getUser());
        assertEquals(workstation, parsed.getWorkstation());

        assertArrayEquals(lmResponse, parsed.getLMResponse());
        assertArrayEquals(ntResponse, parsed.getNTResponse());
    }
}
