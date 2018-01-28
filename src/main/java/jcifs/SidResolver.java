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
package jcifs;


import java.util.List;
import java.util.Map;


/**
 * This is an internal API for resolving SIDs to names and/or retrieving member SIDs
 * 
 * @author mbechler
 * @internal
 */
public interface SidResolver {

    /**
     * Resolve an array of SIDs using a cache and at most one MSRPC request.
     * <p>
     * This method will attempt
     * to resolve SIDs using a cache and cache the results of any SIDs that
     * required resolving with the authority. SID cache entries are currently not
     * expired because under normal circumstances SID information never changes.
     * 
     * @param tc
     *            context to use
     * @param authorityServerName
     *            The hostname of the server that should be queried. For maximum efficiency this should be the hostname
     *            of a domain controller however a member server will work as well and a domain controller may not
     *            return names for SIDs corresponding to local accounts for which the domain controller is not an
     *            authority.
     * @param sids
     *            The SIDs that should be resolved. After this function is called, the names associated with the SIDs
     *            may be queried with the <tt>toDisplayString</tt>, <tt>getDomainName</tt>, and <tt>getAccountName</tt>
     *            methods.
     * @throws CIFSException
     */
    void resolveSids ( CIFSContext tc, String authorityServerName, SID[] sids ) throws CIFSException;


    /**
     * Resolve part of an array of SIDs using a cache and at most one MSRPC request.
     *
     * @param tc
     * @param authorityServerName
     * @param sids
     * @param off
     * @param len
     * @throws CIFSException
     */
    void resolveSids ( CIFSContext tc, String authorityServerName, SID[] sids, int off, int len ) throws CIFSException;


    /**
     * @param tc
     * @param authorityServerName
     * @param domsid
     * @param rid
     * @param flags
     * @return the SIDs of the group members
     * @throws CIFSException
     */
    SID[] getGroupMemberSids ( CIFSContext tc, String authorityServerName, SID domsid, int rid, int flags ) throws CIFSException;


    /**
     * @param authorityServerName
     * @param tc
     * @return the server's SID
     * @throws CIFSException
     */
    SID getServerSid ( CIFSContext tc, String authorityServerName ) throws CIFSException;


    /**
     * This specialized method returns a Map of users and local groups for the
     * target server where keys are SIDs representing an account and each value
     * is an ArrayList of SIDs represents the local groups that the account is
     * a member of.
     * <p/>
     * This method is designed to assist with computing access control for a
     * given user when the target object's ACL has local groups. Local groups
     * are not listed in a user's group membership (e.g. as represented by the
     * tokenGroups constructed attribute retrieved via LDAP).
     * <p/>
     * Domain groups nested inside a local group are currently not expanded. In
     * this case the key (SID) type will be SID_TYPE_DOM_GRP rather than
     * SID_TYPE_USER.
     * 
     * @param tc
     *            The context to use
     * @param authorityServerName
     *            The server from which the local groups will be queried.
     * @param flags
     *            Flags that control the behavior of the operation. When all
     *            name associated with SIDs will be required, the SID_FLAG_RESOLVE_SIDS
     *            flag should be used which causes all group member SIDs to be resolved
     *            together in a single more efficient operation.
     * @return a map of group SID to member SIDs
     * @throws CIFSException
     */
    Map<SID, List<SID>> getLocalGroupsMap ( CIFSContext tc, String authorityServerName, int flags ) throws CIFSException;

}
