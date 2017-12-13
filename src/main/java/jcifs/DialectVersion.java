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
package jcifs;


import java.util.EnumSet;
import java.util.Set;

import jcifs.internal.smb2.Smb2Constants;


/**
 * @author mbechler
 *
 */
public enum DialectVersion {

    /**
     * Legacy SMB1/CIFS
     */
    SMB1,

    /**
     * SMB 2.02 - Windows Vista+
     */
    SMB202(Smb2Constants.SMB2_DIALECT_0202),

    /**
     * SMB 2.1 - Windows 7/Server 2008R2
     */
    SMB210(Smb2Constants.SMB2_DIALECT_0210),

    /**
     * SMB 3.0 - Windows 8/Server 2012
     */
    SMB300(Smb2Constants.SMB2_DIALECT_0300),

    /**
     * SMB 3.0.2 - Windows 8.1/Server 2012R2
     */
    SMB302(Smb2Constants.SMB2_DIALECT_0302),

    /**
     * SMB 3.1.1 - Windows 10/Server 2016
     */
    SMB311(Smb2Constants.SMB2_DIALECT_0311);

    private final boolean smb2;
    private final int dialect;


    /**
     * 
     */
    private DialectVersion () {
        this.smb2 = false;
        this.dialect = -1;
    }


    private DialectVersion ( int dialectId ) {
        this.smb2 = true;
        this.dialect = dialectId;
    }


    /**
     * @return the smb2
     */
    public final boolean isSMB2 () {
        return this.smb2;
    }


    /**
     * @return the dialect
     */
    public final int getDialect () {
        if ( !this.smb2 ) {
            throw new UnsupportedOperationException();
        }
        return this.dialect;
    }


    /**
     * 
     * @param v
     * @return whether this version is a least the given one
     */
    public boolean atLeast ( DialectVersion v ) {
        return ordinal() >= v.ordinal();
    }


    /**
     * 
     * @param v
     * @return whether this version is a most the given one
     */
    public boolean atMost ( DialectVersion v ) {
        return ordinal() <= v.ordinal();
    }


    /**
     * 
     * @param a
     * @param b
     * @return smaller of the two versions
     */
    public static DialectVersion min ( DialectVersion a, DialectVersion b ) {
        if ( a.atMost(b) ) {
            return a;
        }
        return b;
    }


    /**
     * 
     * @param a
     * @param b
     * @return larger of the two versions
     */
    public static DialectVersion max ( DialectVersion a, DialectVersion b ) {
        if ( a.atLeast(b) ) {
            return a;
        }
        return b;
    }


    /**
     * @param min
     *            may be null for open end
     * @param max
     *            may be null for open end
     * @return range of versions
     */
    public static Set<DialectVersion> range ( DialectVersion min, DialectVersion max ) {
        EnumSet<DialectVersion> vers = EnumSet.noneOf(DialectVersion.class);
        for ( DialectVersion ver : values() ) {

            if ( min != null && !ver.atLeast(min) ) {
                continue;
            }

            if ( max != null && !ver.atMost(max) ) {
                continue;
            }

            vers.add(ver);
        }
        return vers;
    }

}
