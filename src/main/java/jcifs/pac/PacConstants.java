/*
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
package jcifs.pac;


@SuppressWarnings ( "javadoc" )
public interface PacConstants {

    static final int PAC_VERSION = 0;

    static final int LOGON_INFO = 1;
    static final int CREDENTIAL_TYPE = 2;
    static final int SERVER_CHECKSUM = 6;
    static final int PRIVSVR_CHECKSUM = 7;

    static final int CLIENT_NAME_TYPE = 0xA;
    static final int CONSTRAINT_DELEGATIION_TYPE = 0xB;
    static final int CLIENT_UPN_TYPE = 0xC;
    static final int CLIENT_CLAIMS_TYPE = 0xD;
    static final int DEVICE_INFO_TYPE = 0xE;
    static final int DEVICE_CLAIMS_TYPE = 0xF;

    static final int LOGON_EXTRA_SIDS = 0x20;
    static final int LOGON_RESOURCE_GROUPS = 0x200;

    static final int MD5_KRB_SALT = 17;
    static final int MD5_BLOCK_LENGTH = 64;

}
