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


import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jcifs.SmbConstants;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileOutputStream;


/**
 * 
 * 
 * 
 * @author Ilan Goldfeld
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class InfoOnLock extends BaseCIFSTest {

    public InfoOnLock ( String name, Map<String, String> properties ) {
        super(name, properties);
    }
    
    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb1", "noUnicode", "forceUnicode", "noNTStatus", "noNTSmbs", "smb2", "smb30", "smb31");
    }

    

    @Test
    public void testExistsOnLock () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            SmbFileOutputStream ostream = f.openOutputStream(true, SmbConstants.FILE_NO_SHARE);
            SmbFile checkFile = new SmbFile(f.getCanonicalPath(), f.getContext());

            try {
            	assertTrue(checkFile.exists());
            } finally {
                ostream.close();
                checkFile.close();
                f.delete();
            }
        }
    }
    
    @Test
    public void testSizeOnLock () throws IOException {
        try ( SmbFile f = createTestFile() ) {
            SmbFileOutputStream ostream = f.openOutputStream(true, SmbConstants.FILE_NO_SHARE);
            SmbFile checkFile = new SmbFile(f.getCanonicalPath(), f.getContext());
            try {
            	assertNotEquals(checkFile.length(), -1);
            } finally {
                ostream.close();
                checkFile.close();
                f.delete();
            }
        }
    }

}
