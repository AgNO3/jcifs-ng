/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 29.01.2016 by mbechler
 */
package jcifs;


import java.util.ArrayList;
import java.util.Map;

import jcifs.smb.SID;


/**
 * @author mbechler
 *
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
     * @param authorityServerName
     *            The hostname of the server that should be queried. For maximum efficiency this should be the hostname
     *            of a domain controller however a member server will work as well and a domain controller may not
     *            return names for SIDs corresponding to local accounts for which the domain controller is not an
     *            authority.
     * @param auth
     *            The credentials that should be used to communicate with the named server. As usual, <tt>null</tt>
     *            indicates that default credentials should be used.
     * @param sids
     *            The SIDs that should be resolved. After this function is called, the names associated with the SIDs
     *            may be queried with the <tt>toDisplayString</tt>, <tt>getDomainName</tt>, and <tt>getAccountName</tt>
     *            methods.
     */
    void resolveSids ( CIFSContext tc, String authorityServerName, SID[] sids ) throws CIFSException;


    void resolveSids ( CIFSContext tc, String server, SID[] sids, int off, int len ) throws CIFSException;


    /**
     * @param tc
     * @param authorityServerName
     * @param domsid
     * @param rid
     * @param flags
     * @return
     * @throws IOException
     */
    SID[] getGroupMemberSids ( CIFSContext tc, String authorityServerName, SID domsid, int rid, int flags ) throws CIFSException;


    /**
     * @param authorityServerName
     * @param tc
     * @return
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
     * tokenGroups constructed attribute retrived via LDAP).
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
     */
    Map<SID, ArrayList<SID>> getLocalGroupsMap ( CIFSContext tc, String authorityServerName, int flags ) throws CIFSException;

}
