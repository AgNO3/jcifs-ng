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


import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Date;

import jcifs.smb.SID;


@SuppressWarnings ( "javadoc" )
public class PacLogonInfo {

    private Date logonTime;
    private Date logoffTime;
    private Date kickOffTime;
    private Date pwdLastChangeTime;
    private Date pwdCanChangeTime;
    private Date pwdMustChangeTime;
    private short logonCount;
    private short badPasswordCount;
    private String userName;
    private String userDisplayName;
    private String logonScript;
    private String profilePath;
    private String homeDirectory;
    private String homeDrive;
    private String serverName;
    private String domainName;
    private SID userSid;
    private SID groupSid;
    private SID[] groupSids;
    private SID[] resourceGroupSids;
    private SID[] extraSids;
    private int userAccountControl;
    private int userFlags;


    public PacLogonInfo ( byte[] data ) throws PACDecodingException {
        try {
            PacDataInputStream pacStream = new PacDataInputStream(new DataInputStream(new ByteArrayInputStream(data)));

            // Skip firsts
            pacStream.skipBytes(20);

            // Dates
            this.logonTime = pacStream.readFiletime();
            this.logoffTime = pacStream.readFiletime();
            this.kickOffTime = pacStream.readFiletime();
            this.pwdLastChangeTime = pacStream.readFiletime();
            this.pwdCanChangeTime = pacStream.readFiletime();
            this.pwdMustChangeTime = pacStream.readFiletime();

            // User related strings as UnicodeStrings
            PacUnicodeString userNameString = pacStream.readUnicodeString();
            PacUnicodeString userDisplayNameString = pacStream.readUnicodeString();
            PacUnicodeString logonScriptString = pacStream.readUnicodeString();
            PacUnicodeString profilePathString = pacStream.readUnicodeString();
            PacUnicodeString homeDirectoryString = pacStream.readUnicodeString();
            PacUnicodeString homeDriveString = pacStream.readUnicodeString();

            // Some counts
            this.logonCount = pacStream.readShort();
            this.badPasswordCount = pacStream.readShort();

            // IDs for user
            SID userId = pacStream.readId();
            SID groupId = pacStream.readId();

            // Groups information
            int groupCount = pacStream.readInt();
            int groupPointer = pacStream.readInt();

            // User flags about PAC Logon Info content
            this.userFlags = pacStream.readInt();
            boolean hasExtraSids = ( this.userFlags & PacConstants.LOGON_EXTRA_SIDS ) == PacConstants.LOGON_EXTRA_SIDS;
            boolean hasResourceGroups = ( this.userFlags & PacConstants.LOGON_RESOURCE_GROUPS ) == PacConstants.LOGON_RESOURCE_GROUPS;

            // Skip some reserved fields (User Session Key)
            pacStream.skipBytes(16);

            // Server related strings as UnicodeStrings
            PacUnicodeString serverNameString = pacStream.readUnicodeString();
            PacUnicodeString domainNameString = pacStream.readUnicodeString();

            // ID for domain (used with relative IDs to get SIDs)
            int domainIdPointer = pacStream.readInt();

            // Skip some reserved fields
            pacStream.skipBytes(8);

            this.userAccountControl = pacStream.readInt();

            // Skip some reserved fields
            pacStream.skipBytes(28);

            // Extra SIDs information
            int extraSidCount = pacStream.readInt();
            int extraSidPointer = pacStream.readInt();

            // ID for resource groups domain (used with IDs to get SIDs)
            int resourceDomainIdPointer = pacStream.readInt();

            // Resource groups information
            int resourceGroupCount = pacStream.readInt();
            int resourceGroupPointer = pacStream.readInt();

            // User related strings
            this.userName = userNameString.check(pacStream.readString());
            this.userDisplayName = userDisplayNameString.check(pacStream.readString());
            this.logonScript = logonScriptString.check(pacStream.readString());
            this.profilePath = profilePathString.check(pacStream.readString());
            this.homeDirectory = homeDirectoryString.check(pacStream.readString());
            this.homeDrive = homeDriveString.check(pacStream.readString());

            // Groups data
            PacGroup[] groups = new PacGroup[0];
            if ( groupPointer != 0 ) {
                int realGroupCount = pacStream.readInt();
                if ( realGroupCount != groupCount ) {
                    throw new PACDecodingException("Invalid number of groups in PAC expect" + groupCount + " have " + realGroupCount);
                }
                groups = new PacGroup[groupCount];
                for ( int i = 0; i < groupCount; i++ ) {
                    pacStream.align(4);
                    SID id = pacStream.readId();
                    int attributes = pacStream.readInt();
                    groups[ i ] = new PacGroup(id, attributes);
                }
            }

            // Server related strings
            this.serverName = serverNameString.check(pacStream.readString());
            this.domainName = domainNameString.check(pacStream.readString());

            // ID for domain (used with relative IDs to get SIDs)
            SID domainId = null;
            if ( domainIdPointer != 0 )
                domainId = pacStream.readSid();

            // Extra SIDs data
            PacSidAttributes[] extraSidAtts = new PacSidAttributes[0];
            if ( hasExtraSids && extraSidPointer != 0 ) {
                int realExtraSidCount = pacStream.readInt();
                if ( realExtraSidCount != extraSidCount ) {
                    throw new PACDecodingException("Invalid number of SIDs in PAC expect" + extraSidCount + " have " + realExtraSidCount);
                }
                extraSidAtts = new PacSidAttributes[extraSidCount];
                int[] pointers = new int[extraSidCount];
                int[] attributes = new int[extraSidCount];
                for ( int i = 0; i < extraSidCount; i++ ) {
                    pointers[ i ] = pacStream.readInt();
                    attributes[ i ] = pacStream.readInt();
                }
                for ( int i = 0; i < extraSidCount; i++ ) {
                    SID sid = ( pointers[ i ] != 0 ) ? pacStream.readSid() : null;
                    extraSidAtts[ i ] = new PacSidAttributes(sid, attributes[ i ]);
                }
            }

            // ID for resource domain (used with relative IDs to get SIDs)
            SID resourceDomainId = null;
            if ( resourceDomainIdPointer != 0 )
                resourceDomainId = pacStream.readSid();

            // Resource groups data
            PacGroup[] resourceGroups = new PacGroup[0];
            if ( hasResourceGroups && resourceGroupPointer != 0 ) {
                int realResourceGroupCount = pacStream.readInt();
                if ( realResourceGroupCount != resourceGroupCount ) {
                    throw new PACDecodingException(
                        "Invalid number of Resource Groups in PAC expect" + resourceGroupCount + " have " + realResourceGroupCount);
                }
                resourceGroups = new PacGroup[resourceGroupCount];
                for ( int i = 0; i < resourceGroupCount; i++ ) {
                    SID id = pacStream.readSid();
                    int attributes = pacStream.readInt();
                    resourceGroups[ i ] = new PacGroup(id, attributes);
                }
            }

            // Extract Extra SIDs
            this.extraSids = new SID[extraSidAtts.length];
            for ( int i = 0; i < extraSidAtts.length; i++ ) {
                this.extraSids[ i ] = extraSidAtts[ i ].getId();
            }

            // Compute Resource Group IDs with Resource Domain ID to get SIDs
            this.resourceGroupSids = new SID[resourceGroups.length];
            for ( int i = 0; i < resourceGroups.length; i++ ) {
                this.resourceGroupSids[ i ] = new SID(resourceDomainId, resourceGroups[ i ].getId());
            }

            // Compute User IDs with Domain ID to get User SIDs
            // First extra is user if userId is empty
            if ( !userId.isEmpty() && !userId.isBlank() ) {
                this.userSid = new SID(domainId, userId);
            }
            else if ( this.extraSids.length > 0 ) {
                this.userSid = this.extraSids[ 0 ];
            }
            this.groupSid = new SID(domainId, groupId);

            // Compute Group IDs with Domain ID to get Group SIDs
            this.groupSids = new SID[groups.length];
            for ( int i = 0; i < groups.length; i++ ) {
                this.groupSids[ i ] = new SID(domainId, groups[ i ].getId());
            }
        }
        catch ( IOException e ) {
            throw new PACDecodingException("Malformed PAC", e);
        }
    }


    public Date getLogonTime () {
        return this.logonTime;
    }


    public Date getLogoffTime () {
        return this.logoffTime;
    }


    public Date getKickOffTime () {
        return this.kickOffTime;
    }


    public Date getPwdLastChangeTime () {
        return this.pwdLastChangeTime;
    }


    public Date getPwdCanChangeTime () {
        return this.pwdCanChangeTime;
    }


    public Date getPwdMustChangeTime () {
        return this.pwdMustChangeTime;
    }


    public short getLogonCount () {
        return this.logonCount;
    }


    public short getBadPasswordCount () {
        return this.badPasswordCount;
    }


    public String getUserName () {
        return this.userName;
    }


    public String getUserDisplayName () {
        return this.userDisplayName;
    }


    public String getLogonScript () {
        return this.logonScript;
    }


    public String getProfilePath () {
        return this.profilePath;
    }


    public String getHomeDirectory () {
        return this.homeDirectory;
    }


    public String getHomeDrive () {
        return this.homeDrive;
    }


    public String getServerName () {
        return this.serverName;
    }


    public String getDomainName () {
        return this.domainName;
    }


    public SID getUserSid () {
        return this.userSid;
    }


    public SID getGroupSid () {
        return this.groupSid;
    }


    public SID[] getGroupSids () {
        return this.groupSids;
    }


    public SID[] getResourceGroupSids () {
        return this.resourceGroupSids;
    }


    public SID[] getExtraSids () {
        return this.extraSids;
    }


    public int getUserAccountControl () {
        return this.userAccountControl;
    }


    public int getUserFlags () {
        return this.userFlags;
    }

}
