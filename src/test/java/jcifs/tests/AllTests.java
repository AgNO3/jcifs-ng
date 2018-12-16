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
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import org.junit.AfterClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;


/**
 * @author mbechler
 *
 */
@RunWith ( Suite.class )
@SuiteClasses ( {
    ContextConfigTest.class, PACTest.class, NtlmTest.class, FileLocationTest.class, SessionTest.class, KerberosTest.class, TimeoutTest.class,
    SidTest.class, NamingTest.class, DfsTest.class, FileAttributesTest.class, EnumTest.class, PipeTest.class, FileOperationsTest.class,
    WatchTest.class, ReadWriteTest.class, ConcurrencyTest.class, RandomAccessFileTest.class, OplockTests.class
} )

public class AllTests {

    private static final Logger log = LoggerFactory.getLogger(AllTests.class);

    private static Map<String, TestMutation> MUTATIONS = new HashMap<>();

    private static Map<String, CIFSContext> CONTEXT_CACHE = new HashMap<>();

    static {
        MUTATIONS.put("noSigning", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.signingPreferred", "false");
                cfg.put("jcifs.smb.client.signingEnforced", "false");
                return cfg;
            }
        });

        MUTATIONS.put("forceSigning", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.signingPreferred", "true");
                cfg.put("jcifs.smb.client.signingEnforced", "true");
                return cfg;
            }
        });

        MUTATIONS.put("smb1-noSigning", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                cfg.put("jcifs.smb.client.signingPreferred", "false");
                cfg.put("jcifs.smb.client.signingEnforced", "false");
                return cfg;
            }
        });

        MUTATIONS.put("smb1-forceSigning", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                cfg.put("jcifs.smb.client.signingPreferred", "true");
                cfg.put("jcifs.smb.client.signingEnforced", "true");
                return cfg;
            }
        });

        MUTATIONS.put("legacyAuth", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                cfg.put("jcifs.smb.lmCompatibility", "2");
                cfg.put("jcifs.smb.client.useExtendedSecurity", "false");
                cfg.put("jcifs.smb.client.forceExtendedSecurity", "false");
                return cfg;
            }
        });

        MUTATIONS.put("forceSpnegoIntegrity", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.enforceSpnegoIntegrity", "true");
                return cfg;
            }
        });

        MUTATIONS.put("noUnicode", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                cfg.put("jcifs.smb.client.useUnicode", "false");
                cfg.put("jcifs.smb.client.forceUnicode", "false");
                return cfg;
            }
        });

        MUTATIONS.put("forceUnicode", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                cfg.put("jcifs.smb.client.useUnicode", "true");
                cfg.put("jcifs.smb.client.forceUnicode", "true");
                return cfg;
            }
        });

        MUTATIONS.put("noNTStatus", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                cfg.put("jcifs.smb.client.useNtStatus", "false");
                return cfg;
            }
        });

        MUTATIONS.put("noNTSmbs", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                cfg.put("jcifs.smb.client.useNTSmbs", "false");
                return cfg;
            }
        });

        MUTATIONS.put("noUnicode-cp850", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                cfg.put("jcifs.smb.client.useUnicode", "false");
                cfg.put("jcifs.encoding", "cp850");
                return cfg;
            }
        });

        MUTATIONS.put("noUnicode-windows-1252", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                cfg.put("jcifs.smb.client.useUnicode", "false");
                cfg.put("jcifs.encoding", "windows-1252");
                return cfg;
            }
        });

        MUTATIONS.put("noLargeReadWrite", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                cfg.put("jcifs.smb.client.useLargeReadWrite", "false");
                return cfg;
            }
        });

        MUTATIONS.put("smb1", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.maxVersion", "SMB1");
                return cfg;
            }
        });

        MUTATIONS.put("smb2", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.minVersion", "SMB202");
                cfg.put("jcifs.smb.client.maxVersion", "SMB210");
                return cfg;
            }
        });

        MUTATIONS.put("smb30", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.minVersion", "SMB300");
                cfg.put("jcifs.smb.client.maxVersion", "SMB302");
                return cfg;
            }
        });

        MUTATIONS.put("smb31", new TestMutation() {

            @Override
            public Map<String, String> mutate ( Map<String, String> cfg ) {
                cfg.put("jcifs.smb.client.minVersion", "SMB311");
                cfg.put("jcifs.smb.client.maxVersion", "SMB311");
                return cfg;
            }
        });
    }


    /**
     * @throws CIFSException
     */
    @AfterClass
    public static void closeContexts () throws CIFSException {
        for ( Entry<String, CIFSContext> ctx : CONTEXT_CACHE.entrySet() ) {
            if ( ctx.getValue().close() ) {
                log.error("Context was still in use " + ctx.getKey());
            }
        }
    }


    static CIFSContext getCachedContext ( String context, Properties props ) throws CIFSException {
        CIFSContext cached = CONTEXT_CACHE.get(context);
        if ( cached == null ) {
            cached = new BaseContext(new PropertyConfiguration(props));
            CONTEXT_CACHE.put(context, cached);
        }
        return cached;
    }


    /**
     * @param applyMutations
     * @return configurations available for running
     * 
     */
    public synchronized static Map<String, Map<String, String>> getConfigs ( String[] applyMutations ) {
        Map<String, Map<String, String>> configs = new HashMap<>();

        if ( System.getProperties().containsKey(TestProperties.TEST_SERVER) ) {
            configs.put("properties", toMap(System.getProperties()));
        }

        if ( System.getProperties().containsKey(TestProperties.TEST_CONFIG_DIR) ) {
            try {
                Path configDir = Paths.get(System.getProperty(TestProperties.TEST_CONFIG_DIR));
                Iterator<Path> it = Files.newDirectoryStream(configDir).iterator();

                while ( it.hasNext() ) {
                    Path config = it.next();
                    String fname = config.getFileName().toString();
                    if ( !fname.endsWith(".conf") ) {
                        continue;
                    }
                    Properties props = new Properties();
                    try ( FileChannel ch = FileChannel.open(config, StandardOpenOption.READ);
                          InputStream is = Channels.newInputStream(ch) ) {
                        props.load(is);

                    }
                    if ( !props.isEmpty() ) {
                        Map<String, String> map = toMap(props);
                        String cfgname = fname.substring(0, fname.length() - 5);
                        configs.put(cfgname, map);
                        Set<String> apply = new HashSet<>(Arrays.asList(applyMutations));

                        Set<String> excludes = new HashSet<>();
                        if ( map.get(TestProperties.EXCLUDE_TEST_MUTATIONS) != null ) {
                            excludes.addAll(Arrays.asList(map.get(TestProperties.EXCLUDE_TEST_MUTATIONS).split("\\s*,\\s*")));
                        }
                        if ( applyMutations != null && applyMutations.length > 0 && map.get(TestProperties.TEST_MUTATIONS) != null ) {
                            for ( String mutate : map.get(TestProperties.TEST_MUTATIONS).split("\\s*,\\s*") ) {
                                if ( excludes.contains(mutate) || shouldSkip(excludes, mutate) ) {
                                    continue;
                                }
                                if ( apply.contains(mutate) && MUTATIONS.containsKey(mutate) ) {
                                    configs.put(cfgname + "-" + mutate, MUTATIONS.get(mutate).mutate(new HashMap<>(map)));
                                }
                            }
                        }
                        else if ( applyMutations != null && applyMutations.length > 0 ) {
                            for ( String mutate : applyMutations ) {
                                if ( excludes.contains(mutate) || shouldSkip(excludes, mutate) ) {
                                    continue;
                                }
                                if ( MUTATIONS.containsKey(mutate) ) {
                                    configs.put(cfgname + "-" + mutate, MUTATIONS.get(mutate).mutate(new HashMap<>(map)));
                                }
                            }
                        }
                    }
                }
            }
            catch ( IOException e ) {
                log.error("Failed to load test config directory " + System.getProperty(TestProperties.TEST_CONFIG_DIR), e);
            }
        }
        return configs;
    }


    /**
     * @param excludes
     * @param mutate
     * @return
     */
    private static boolean shouldSkip ( Set<String> excludes, String mutate ) {
        boolean skip = false;
        for ( String exclude : excludes ) {
            if ( mutate.startsWith(exclude) ) {
                skip = true;
                break;
            }
        }
        return skip;
    }


    /**
     * @return
     */
    static Map<String, String> toMap ( Properties props ) {
        Map<String, String> res = new HashMap<>();
        for ( Object object : props.keySet() ) {
            res.put((String) object, props.getProperty((String) object).trim());
        }
        return res;
    }

}
