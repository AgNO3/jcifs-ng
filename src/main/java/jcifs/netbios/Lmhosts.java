/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.netbios;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.smb.SmbFileInputStream;


/**
 * 
 *
 */
public class Lmhosts {

    private static final Logger log = LoggerFactory.getLogger(Lmhosts.class);

    private final Map<Name, NbtAddress> table = new HashMap<>();
    private long lastModified = 1L;
    private int alt;


    /**
     * This is really just for {@link jcifs.netbios.UniAddress}. It does
     * not throw an {@link java.net.UnknownHostException} because this
     * is queried frequently and exceptions would be rather costly to
     * throw on a regular basis here.
     * 
     * @param host
     * @param tc
     * @return resolved name, null if not found
     */
    public synchronized NbtAddress getByName ( String host, CIFSContext tc ) {
        return getByName(new Name(tc.getConfig(), host, 0x20, null), tc);
    }


    synchronized NbtAddress getByName ( Name name, CIFSContext tc ) {
        NbtAddress result = null;

        try {
            if ( tc.getConfig().getLmHostsFileName() != null ) {
                File f = new File(tc.getConfig().getLmHostsFileName());
                long lm;

                if ( ( lm = f.lastModified() ) > this.lastModified ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug("Reading " + tc.getConfig().getLmHostsFileName());
                    }
                    this.lastModified = lm;
                    this.table.clear();
                    try ( FileReader r = new FileReader(f) ) {
                        populate(r, tc);
                    }
                }
                result = this.table.get(name);
            }
        }
        catch ( IOException fnfe ) {
            log.error("Could not read lmhosts " + tc.getConfig().getLmHostsFileName(), fnfe); //$NON-NLS-1$
        }
        return result;
    }


    void populate ( Reader r, CIFSContext tc ) throws IOException {
        String line;
        BufferedReader br = new BufferedReader(r);

        while ( ( line = br.readLine() ) != null ) {
            line = line.toUpperCase().trim();
            if ( line.length() == 0 ) {
                continue;
            }
            else if ( line.charAt(0) == '#' ) {
                if ( line.startsWith("#INCLUDE ") ) {
                    line = line.substring(line.indexOf('\\'));
                    String url = "smb:" + line.replace('\\', '/');

                    try ( InputStreamReader rdr = new InputStreamReader(new SmbFileInputStream(url, tc)) ) {
                        if ( this.alt > 0 ) {
                            try {
                                populate(rdr, tc);
                            }
                            catch ( IOException ioe ) {
                                log.error("Failed to read include " + url, ioe);
                                continue;
                            }

                            /*
                             * An include was loaded successfully. We can skip
                             * all other includes up to the #END_ALTERNATE tag.
                             */

                            while ( ( line = br.readLine() ) != null ) {
                                line = line.toUpperCase().trim();
                                if ( line.startsWith("#END_ALTERNATE") ) {
                                    break;
                                }
                            }
                        }
                        else {
                            populate(rdr, tc);
                        }
                    }
                }
                else if ( line.startsWith("#BEGIN_ALTERNATE") ) {}
                else if ( line.startsWith("#END_ALTERNATE") && this.alt > 0 ) {
                    throw new IOException("no lmhosts alternate includes loaded");
                }
            }
            else if ( Character.isDigit(line.charAt(0)) ) {
                char[] data = line.toCharArray();
                int ip, i, j;
                Name name;
                NbtAddress addr;
                char c;

                c = '.';
                ip = i = 0;
                for ( ; i < data.length && c == '.'; i++ ) {
                    int b = 0x00;

                    for ( ; i < data.length && ( c = data[ i ] ) >= 48 && c <= 57; i++ ) {
                        b = b * 10 + c - '0';
                    }
                    ip = ( ip << 8 ) + b;
                }
                while ( i < data.length && Character.isWhitespace(data[ i ]) ) {
                    i++;
                }
                j = i;
                while ( j < data.length && Character.isWhitespace(data[ j ]) == false ) {
                    j++;
                }

                name = new Name(tc.getConfig(), line.substring(i, j), 0x20, null);
                addr = new NbtAddress(name, ip, false, NbtAddress.B_NODE, false, false, true, true, NbtAddress.UNKNOWN_MAC_ADDRESS);
                if ( log.isDebugEnabled() ) {
                    log.debug("Adding " + name + " with addr " + addr);
                }
                this.table.put(name, addr);
            }
        }
    }
}
