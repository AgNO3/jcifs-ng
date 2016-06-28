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


import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;


/**
 * @author mbechler
 *
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class FileOperationsTest extends BaseCIFSTest {

    public FileOperationsTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Test
    public void testRenameFile () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile defaultShareRoot = getDefaultShareRoot();
        SmbFile f = new SmbFile(defaultShareRoot, makeRandomName());
        SmbFile f2 = new SmbFile(defaultShareRoot, makeRandomName());
        f.createNewFile();
        boolean renamed = false;
        try {
            f.renameTo(f2);
            try {
                assertTrue(f2.exists());
                renamed = true;
            }
            finally {
                f2.delete();
            }
        }
        finally {
            if ( !renamed && f.exists() ) {
                f.delete();
            }
        }
    }


    @Test
    public void testMoveFile () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile defaultShareRoot = getDefaultShareRoot();
        SmbFile d = createTestDirectory();
        SmbFile f = new SmbFile(defaultShareRoot, makeRandomName());
        SmbFile f2 = new SmbFile(d, makeRandomName());
        f.createNewFile();
        boolean renamed = false;
        try {
            f.renameTo(f2);
            try {
                assertTrue(f2.exists());
                renamed = true;
            }
            finally {
                f2.delete();
            }
        }
        finally {
            if ( !renamed && f.exists() ) {
                f.delete();
            }
            d.delete();
        }
    }


    @Test
    public void testRenameDirectory () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile defaultShareRoot = getDefaultShareRoot();
        SmbFile d = createTestDirectory();
        SmbFile d1 = new SmbFile(defaultShareRoot, makeRandomDirectoryName());
        SmbFile d2 = new SmbFile(d, makeRandomDirectoryName());
        d1.mkdir();
        boolean renamed = false;
        try {
            d1.renameTo(d2);
            try {
                assertTrue(d2.exists());
                renamed = true;
            }
            finally {
                d2.delete();
            }
        }
        finally {
            if ( !renamed && d1.exists() ) {
                d1.delete();
            }
            d.delete();
        }
    }


    @Test
    public void testMoveDirectory () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile defaultShareRoot = getDefaultShareRoot();
        SmbFile d1 = new SmbFile(defaultShareRoot, makeRandomDirectoryName());
        SmbFile d2 = new SmbFile(defaultShareRoot, makeRandomDirectoryName());
        d1.mkdir();
        boolean renamed = false;
        try {
            d1.renameTo(d2);
            try {
                assertTrue(d2.exists());
                renamed = true;
            }
            finally {
                d2.delete();
            }
        }
        finally {
            if ( !renamed && d1.exists() ) {
                d1.delete();
            }
        }
    }


    @Test
    public void testCopyFile () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile f = createTestFile();
        try {
            SmbFile d1 = createTestDirectory();
            SmbFile t = new SmbFile(d1, makeRandomName());
            try {
                f.copyTo(t);
                assertTrue(f.exists());
            }
            finally {
                d1.delete();
            }
        }
        finally {
            f.delete();
        }
    }


    @Test
    public void testCopyDir () throws SmbException, MalformedURLException, UnknownHostException {
        SmbFile f = createTestDirectory();
        SmbFile e = new SmbFile(f, "test");
        e.createNewFile();
        try {
            SmbFile d1 = createTestDirectory();
            SmbFile t = new SmbFile(d1, makeRandomName());
            try {
                f.copyTo(t);
                assertTrue(f.exists());

                SmbFile e2 = new SmbFile(t, "test");
                assertTrue(e2.exists());
            }
            finally {
                d1.delete();
            }
        }
        finally {
            f.delete();
        }
    }
}
