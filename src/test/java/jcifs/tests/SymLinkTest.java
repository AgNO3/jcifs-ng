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
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;


/**
 * The actual SMB share must be configured in the system properties
 * with the 'real' server settings for testing.
 *
 * You must create the following folder structures in your SMB share
 * for a successful completion of these unit tests:
 *
 * <pre class="code">
 *  smbSource/
 *  |-- subSmbSource/
 *      |-- subSmbSource1.txt - contains 'subSource1'
 *      |-- subSmbSource2.txt - contains 'subSource2'
 *  smbTarget/
 *  |-- foo.file - contains 'foofoofoo'
 *  symlinkTestDir/ - symbolic link to directory smbSource/subSmbSource/
 *                    using 'mklink /D symlinkTestDir <share root>\smbSource\subSmbSource\'
 *  symlinkTestFoo.file - symbolic link to file smbTarget/foo.file
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
        return getConfigs("smb1", "noUnicode", "forceUnicode", "noNTStatus", "noNTSmbs", "smb2", "smb30", "smb31");
    }


    @Test
    public void testSymlink1() throws MalformedURLException, CIFSException {
        SmbFile smbFile = createSession();
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

            if (file.isSymlink()) {
                log.info("Resource [" + file.getName() + "] is a symbolic link.");
            }
            else {
                log.info("Resource [" + file.getName() + "] is not a symbolic link.");
            }

            try {
                InputStream is = file.getInputStream();
                assertNotNull(is);

                if (file.isDirectory()) {
                    log.info("file.list() -> {}", Arrays.toString(file.list()));
                    log.info("file.listFiles() -> {}", Arrays.toString(file.listFiles()));
                }

                if (file.isFile() && file.getName().equals("symlinkTestFoo.file")) {
                    long l = copyInputStreamToFile(is, File.createTempFile(file.getName(), ".txt"));
                    assertTrue("No bytes written", l > 0);
                    assertTrue("Bytes written should be 9", l == 9);
                }
            }
            catch (IOException ioe) {
                throw new SmbException("testSymlink1 error", ioe);
            }
            finally {
                file.close();
            }
        }

        smbFile.close();
    }


    private SmbFile createSession() throws MalformedURLException, CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.minVersion", DialectVersion.SMB210.name());
        props.setProperty("jcifs.smb.client.maxVersion", DialectVersion.SMB311.name());

        SmbFile smbFile = new SmbFile("smb://" + getTestServer() + SMB_FILE_SEPARATOR + getTestShare(),
                new BaseContext(
                    new PropertyConfiguration(props)).withCredentials(
                        new NtlmPasswordAuthenticator(getTestUserDomain(), getTestUser(), getTestUserPassword())));
        return smbFile;
    }


    private long copyInputStreamToFile(InputStream is, File file) throws IOException {
        try (OutputStream output = new FileOutputStream(file)) {
            return is.transferTo(output);
        } catch (IOException ioe) {
            log.error("copyInputStreamToFile error", ioe);
            throw ioe;
        }
    }

}
