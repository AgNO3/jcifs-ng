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


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;

import org.apache.log4j.Logger;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class NamingTest extends BaseCIFSTest {

    public NamingTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("noUnicode", "forceUnicode", "noUnicode-cp850", "noUnicode-windows-1252");
    }


    @Test
    public void testASCII () throws SmbException, MalformedURLException, UnknownHostException {
        runFilenameTest("just-testing", "adsfg.txt");
    }


    @Test
    public void testCodepage () throws SmbException, MalformedURLException, UnknownHostException {
        Assume.assumeFalse("Unicode support", getContext().getConfig().isUseUnicode());
        String oemEncoding = getContext().getConfig().getOemEncoding();
        String str = null;
        try {
            switch ( oemEncoding.toLowerCase(Locale.ROOT) ) {
            case "cp850":
                str = makeCharsetString(Charset.forName(oemEncoding), 128, 256, 240, 255);
                break;
            case "windows-1252":
                str = makeCharsetString(Charset.forName(oemEncoding), 128, 256, 0x81, 0x8D, 0x8F, 0x90, 0x9D);
                break;
            default:
                Assume.assumeTrue("Unhandled OEM encoding " + oemEncoding, false);
            }
        }
        catch ( UnsupportedCharsetException e ) {
            Assume.assumeTrue("Charset is not supported on this VM " + oemEncoding, false);
        }
        runFilenameTest(splitString(str, 8));
    }


    private static String makeCharsetString ( Charset cs, int min, int max, int... excludes ) {
        ByteBuffer buf = ByteBuffer.allocate(128);
        Arrays.sort(excludes);
        for ( int i = 128; i < 255; i++ ) {
            int idx = Arrays.binarySearch(excludes, i);
            if ( idx < 0 || excludes[ idx ] == i ) {
                continue;
            }

            if ( i == 240 ) {
                continue;
            }
            buf.put((byte) i);
        }
        buf.flip();
        String str = cs.decode(buf).toString();
        return str;
    }


    private static String[] splitString ( String str, int maxLen ) {
        int num = str.length() / maxLen;
        if ( str.length() % maxLen != 0 ) {
            num++;
        }
        String strings[] = new String[num];
        for ( int i = 0; i < num; i++ ) {
            strings[ i ] = str.substring(i * maxLen, Math.min(str.length() - 1, ( i + 1 ) * maxLen));
        }
        return strings;
    }


    @Test
    public void testUnicode () throws SmbException, MalformedURLException, UnknownHostException {
        Assume.assumeTrue("No unicode support", getContext().getConfig().isUseUnicode());
        runFilenameTest(Strings.UNICODE_STRINGS);
    }


    private void runFilenameTest ( String... names ) throws MalformedURLException, UnknownHostException, SmbException {
        SmbFile d = createTestDirectory();
        try {

            for ( String name : names ) {
                SmbFile tf = new SmbFile(d, name);
                tf.createNewFile();
            }

            // check that the expected name is returned from listing

            String[] found = d.list();
            String[] expect = names;

            Arrays.sort(found);
            Arrays.sort(expect);

            Logger logger = Logger.getLogger(NamingTest.class);
            if ( logger.isDebugEnabled() ) {
                logger.debug("Expect " + Arrays.toString(expect));
                logger.debug("Found " + Arrays.toString(found));
            }

            assertArrayEquals(expect, found);

            // check that the name can be resolved via URL
            URL purl = d.getURL();
            for ( String name : names ) {
                URL u = new URL(purl, name);
                SmbFile tf = new SmbFile(u, d.getTransportContext());
                assertTrue("File exists " + u, tf.exists());
                assertEquals(name, tf.getName());
            }
        }
        finally {
            d.delete();
        }
    }

}
