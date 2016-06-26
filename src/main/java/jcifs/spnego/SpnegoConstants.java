/* jcifs smb client library in Java
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package jcifs.spnego;


@SuppressWarnings ( "javadoc" )
public interface SpnegoConstants {

    public static final String SPNEGO_MECHANISM = "1.3.6.1.5.5.2";

    public static final String KERBEROS_MECHANISM = "1.2.840.113554.1.2.2";

    public static final String LEGACY_KERBEROS_MECHANISM = "1.2.840.48018.1.2.2";

    public static final String NTLMSSP_MECHANISM = "1.3.6.1.4.1.311.2.2.10";

}
