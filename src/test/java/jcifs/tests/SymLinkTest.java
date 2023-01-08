/*
 * © 2022 AgNO3 Gmbh & Co. KG
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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Properties;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.DialectVersion;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbFile;


/**
 * The actual SMB share must be configured in the system properties
 * with the 'real' server settings for testing.
 *
 * You must create the following folder structures in your SMB share
 * for a successful completion of these unit tests:
 *
 * <pre class="code">
 *  smbSource\
 *  |-- subSmbSource\
 *      |-- subSmbSource1.txt - contains 'subSource1'
 *      |-- subSmbSource2.txt - contains 'subSource2'
 *      |-- symlinkRelativeTest2Dir\ - relative symlink to directory \smbTarget\
 *                                     using 'mklink /D symlinkRelativeTest2Dir ..\..\smbTarget'
 *      |-- symlinkRelative2Foo.file - relative symlink to \smbTarget\foo.file 
 *                                     using 'mklink symlinkRelative2Foo.file ..\..\smbTarget\foo.file'
 *  smbTarget\
 *  |-- foo.file - contains 'foofoofoo'
 *  symlinkRelativeTestDir\ - relative symbolic link to directory \smbSource\subSmbSource\
 *                            using 'mklink /D symlinkRelativeTestDir smbSource\subSmbSource'
 *  symlinkTestDir\ - absolute symbolic link to directory \smbSource\subSmbSource\
 *                    using 'mklink /D symlinkTestDir <share root>\smbSource\subSmbSource\'
 *  symlinkRelativeFoo.file - relative symbolic link to file \smbTarget\foo.file
 *                            using 'mklink symlinkTestFoo.file \smbTarget\foo.file'
 *  symlinkTestFoo.file - absolute symbolic link to file \smbTarget\foo.file
 *                        using 'mklink symlinkTestFoo.file <share root>\smbTarget\foo.file'
 * </pre>
 *
 * @author Gregory Bragg
 */
@RunWith ( Parameterized.class )
@SuppressWarnings ( "javadoc" )
public class SymLinkTest extends BaseCIFSTest {

    private static final Logger log = LoggerFactory.getLogger(SymLinkTest.class);

    private static final String SMB_FILE_SEPARATOR = "/";

    public SymLinkTest ( String name, Map<String, String> properties ) {
        super(name, properties);
    }


    @Parameters ( name = "{0}" )
    public static Collection<Object> configs () {
        return getConfigs("smb31");
    }


    @Test
    public void testSymlink1 () throws MalformedURLException, CIFSException {
        try ( SmbFile smbFile = createSession() ) {
//        try ( SmbFile smbFile = this.getDefaultShareRoot() ) {
            assertNotNull(smbFile);

            SmbFile[] files = smbFile.listFiles();
            log.info(Arrays.toString(files));
            assertNotNull(files);
            assertTrue("No share found", files.length > 0);

            for (SmbFile file : files) {
                assertNotNull(file);

                if (file.isDirectory()) {
                    log.info("Resource [" + file.getName() + "] is a directory.");
                }
                else {
                    log.info("Resource [" + file.getName() + "] is not a directory.");
                }

                if (file.isFile()) {
                    log.info("Resource [" + file.getName() + "] is a file.");
                }
                else {
                    log.info("Resource [" + file.getName() + "] is not a file.");
                }

                if (file.isSymLink()) {
                    log.info("Resource [" + file.getName() + "] is a symbolic link.");
                }
                else {
                    log.info("Resource [" + file.getName() + "] is not a symbolic link.");
                }

                InputStream is = null;
                try {
                    is = file.getInputStream();
                    assertNotNull(is);
                }
                catch (IOException ioe1) {
                    log.error("testSymlink1 error on opening input stream, 1st time", ioe1);

                    if (ioe1.getCause().getClass().equals(SMBProtocolDecodingException.class)) {
                        String symLinkPath = file.getSymLinkTargetPath();
                        log.info("SymLink Path -> {}", symLinkPath);

                        String targetPath = "";
                        try {
                            int i = symLinkPath.lastIndexOf(getTestShare().replace("/", "\\"));
                            if (i != -1) {
                                targetPath = symLinkPath.substring(i + getTestShare().length());
                                log.info("Target Path -> {}", targetPath);
                            }

                            file = new SmbFile(
                                    "smb://" + getTestServer() + SMB_FILE_SEPARATOR + getTestShare() + targetPath.replace("\\", "/"),
                                    file.getContext());
                            assertNotNull(file);

                            is = file.getInputStream();
                            assertNotNull(is);
                        }
                        catch (IOException ioe2) {
                            log.error("testSymlink1 error on opening input stream for symlink target path, 2nd time", ioe2);
                        }
                    }
                }

                try {
                    if (file.isDirectory()) {
                        log.info("file.list() -> {}", Arrays.toString(file.list()));

                        if (file.getName().equals("symlinkTestDir/") || file.getName().equals("symlinkRelativeTest2Dir/")) {
                            SmbFile[] files2 = file.listFiles();
                            assertNotNull(files2);
                            log.info("file.listFiles() -> {}", Arrays.toString(files2));

                            for (SmbFile file2 : files2) {
                                log.info("file2.getName() -> {}", file2.getName());

                                InputStream is2 = file2.getInputStream();
                                assertNotNull(is2);

                                if (!file2.getName().equals("symlinkRelativeTest2Dir/")) {
                                    long l2 = copyInputStreamToFile(is2, File.createTempFile(file2.getName(), ".txt"));
                                    assertTrue("No bytes written", l2 > 0);

                                    if (file2.getName().equals("symlinkRelative2Foo.file")) {
                                        assertTrue("Bytes written should be 9", l2 == 9);
                                    }
                                    else {
                                        assertTrue("Bytes written should be 10", l2 == 10);
                                    }
                                }
                            }
                        }
                    }

                    if (file.isFile() && file.getName().equals("symlinkTestFoo.file")) {
                        long l = copyInputStreamToFile(is, File.createTempFile(file.getName(), ".txt"));
                        assertTrue("No bytes written", l > 0);
                        assertTrue("Bytes written should be 9", l == 9);
                    }
                }
                catch (IOException ioe3) {
                    log.error("testSymlink1 error", ioe3);
                }
                finally {
                    file.close();
                }
            }
        }
    }


    private SmbFile createSession() throws MalformedURLException, CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.minVersion", DialectVersion.SMB311.name());
        //props.setProperty("jcifs.smb.client.maxVersion", DialectVersion.SMB311.name());

        SmbFile smbFile = new SmbFile("smb://" + getTestServer() + SMB_FILE_SEPARATOR + getTestShare() + SMB_FILE_SEPARATOR,
                new BaseContext(
                    new PropertyConfiguration(props)).withCredentials(
                        new NtlmPasswordAuthenticator(getTestUserDomain(), getTestUser(), getTestUserPassword())));
        return smbFile;
    }


    private long copyInputStreamToFile(InputStream is, File file) throws IOException {
        try (OutputStream output = new FileOutputStream(file)) {
            int read = 0;
            long total = 0;
            byte[] buffer = new byte[1024];

            while ( (read = is.read(buffer)) != 0 ) {
                output.write(buffer, 0, read);
                total += read;
            }
            return total;
        } catch (IOException ioe) {
            log.error("copyInputStreamToFile error", ioe);
            throw ioe;
        }
    }

}
