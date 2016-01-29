/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 29.01.2016 by mbechler
 */
package jcifs.smb;


import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SidResolver;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.UnicodeString;
import jcifs.dcerpc.rpc;
import jcifs.dcerpc.msrpc.LsaPolicyHandle;
import jcifs.dcerpc.msrpc.MsrpcEnumerateAliasesInDomain;
import jcifs.dcerpc.msrpc.MsrpcGetMembersInAlias;
import jcifs.dcerpc.msrpc.MsrpcLookupSids;
import jcifs.dcerpc.msrpc.MsrpcQueryInformationPolicy;
import jcifs.dcerpc.msrpc.SamrAliasHandle;
import jcifs.dcerpc.msrpc.SamrDomainHandle;
import jcifs.dcerpc.msrpc.SamrPolicyHandle;
import jcifs.dcerpc.msrpc.lsarpc;
import jcifs.dcerpc.msrpc.samr;


/**
 * @author mbechler
 *
 */
public class SIDCacheImpl implements SidResolver {

    private Map<SID, SID> sidCache = new HashMap<>();


    /**
     * @param baseContext
     */
    public SIDCacheImpl ( CIFSContext baseContext ) {}


    void resolveSids ( DcerpcHandle handle, LsaPolicyHandle policyHandle, SID[] sids ) throws IOException {
        MsrpcLookupSids rpc = new MsrpcLookupSids(policyHandle, sids);
        handle.sendrecv(rpc);
        switch ( rpc.retval ) {
        case 0:
        case NtStatus.NT_STATUS_NONE_MAPPED:
        case 0x00000107: // NT_STATUS_SOME_NOT_MAPPED
            break;
        default:
            throw new SmbException(rpc.retval, false);
        }

        for ( int si = 0; si < sids.length; si++ ) {
            sids[ si ].type = rpc.names.names[ si ].sid_type;
            sids[ si ].domainName = null;

            switch ( sids[ si ].type ) {
            case SID.SID_TYPE_USER:
            case SID.SID_TYPE_DOM_GRP:
            case SID.SID_TYPE_DOMAIN:
            case SID.SID_TYPE_ALIAS:
            case SID.SID_TYPE_WKN_GRP:
                int sid_index = rpc.names.names[ si ].sid_index;
                rpc.unicode_string ustr = rpc.domains.domains[ sid_index ].name;
                sids[ si ].domainName = ( new UnicodeString(ustr, false) ).toString();
                break;
            }

            sids[ si ].acctName = ( new UnicodeString(rpc.names.names[ si ].name, false) ).toString();
            sids[ si ].origin_server = null;
            sids[ si ].origin_ctx = null;
        }
    }


    void resolveSids0 ( String authorityServerName, CIFSContext tc, SID[] sids ) throws CIFSException {
        LsaPolicyHandle policyHandle = null;

        synchronized ( this.sidCache ) {
            try ( DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + authorityServerName + "[\\PIPE\\lsarpc]", tc) ) {
                String server = authorityServerName;
                int dot = server.indexOf('.');
                if ( dot > 0 && Character.isDigit(server.charAt(0)) == false )
                    server = server.substring(0, dot);
                policyHandle = new LsaPolicyHandle(handle, "\\\\" + server, 0x00000800);
                resolveSids(handle, policyHandle, sids);
            }
            catch ( IOException e ) {
                throw new CIFSException("Failed to resolve SIDs", e);
            }
        }
    }


    @Override
    public void resolveSids ( CIFSContext tc, String authorityServerName, SID[] sids, int offset, int length ) throws CIFSException {
        ArrayList<SID> list = new ArrayList<>(sids.length);
        int si;

        synchronized ( this.sidCache ) {
            for ( si = 0; si < length; si++ ) {
                SID sid = this.sidCache.get(sids[ offset + si ]);
                if ( sid != null ) {
                    sids[ offset + si ].type = sid.type;
                    sids[ offset + si ].domainName = sid.domainName;
                    sids[ offset + si ].acctName = sid.acctName;
                }
                else {
                    list.add(sids[ offset + si ]);
                }
            }

            if ( list.size() > 0 ) {
                sids = list.toArray(new SID[0]);
                resolveSids0(authorityServerName, tc, sids);
                for ( si = 0; si < sids.length; si++ ) {
                    this.sidCache.put(sids[ si ], sids[ si ]);
                }
            }
        }
    }


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
    @Override
    public void resolveSids ( CIFSContext tc, String authorityServerName, SID[] sids ) throws CIFSException {
        ArrayList<SID> list = new ArrayList<>(sids.length);
        int si;

        synchronized ( this.sidCache ) {
            for ( si = 0; si < sids.length; si++ ) {
                SID sid = this.sidCache.get(sids[ si ]);
                if ( sid != null ) {
                    sids[ si ].type = sid.type;
                    sids[ si ].domainName = sid.domainName;
                    sids[ si ].acctName = sid.acctName;
                }
                else {
                    list.add(sids[ si ]);
                }
            }

            if ( list.size() > 0 ) {
                sids = list.toArray(new SID[0]);
                resolveSids0(authorityServerName, tc, sids);
                for ( si = 0; si < sids.length; si++ ) {
                    this.sidCache.put(sids[ si ], sids[ si ]);
                }
            }
        }
    }


    @Override
    public SID getServerSid ( CIFSContext tc, String server ) throws CIFSException {
        LsaPolicyHandle policyHandle = null;
        lsarpc.LsarDomainInfo info = new lsarpc.LsarDomainInfo();
        MsrpcQueryInformationPolicy rpc;

        synchronized ( this.sidCache ) {
            try ( DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + server + "[\\PIPE\\lsarpc]", tc) ) {
                // NetApp doesn't like the 'generic' access mask values
                policyHandle = new LsaPolicyHandle(handle, null, 0x00000001);
                rpc = new MsrpcQueryInformationPolicy(policyHandle, (short) lsarpc.POLICY_INFO_ACCOUNT_DOMAIN, info);
                handle.sendrecv(rpc);
                if ( rpc.retval != 0 )
                    throw new SmbException(rpc.retval, false);

                return new SID(info.sid, SID.SID_TYPE_DOMAIN, ( new UnicodeString(info.name, false) ).toString(), null, false);
            }
            catch ( IOException e ) {
                throw new CIFSException("Failed to get SID from server", e);
            }
        }
    }


    @Override
    public SID[] getGroupMemberSids ( CIFSContext tc, String authorityServerName, SID domsid, int rid, int flags ) throws CIFSException {
        SamrAliasHandle aliasHandle = null;
        lsarpc.LsarSidArray sidarray = new lsarpc.LsarSidArray();
        MsrpcGetMembersInAlias rpc = null;

        synchronized ( this.sidCache ) {
            try ( DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + authorityServerName + "[\\PIPE\\samr]", tc) ) {
                SamrPolicyHandle policyHandle = new SamrPolicyHandle(handle, authorityServerName, 0x00000030);
                SamrDomainHandle domainHandle = new SamrDomainHandle(handle, policyHandle, 0x00000200, domsid);
                try {
                    aliasHandle = new SamrAliasHandle(handle, domainHandle, 0x0002000c, rid);
                    rpc = new MsrpcGetMembersInAlias(aliasHandle, sidarray);
                    handle.sendrecv(rpc);
                    if ( rpc.retval != 0 )
                        throw new SmbException(rpc.retval, false);
                    SID[] sids = new SID[rpc.sids.num_sids];

                    String origin_server = handle.getServer();
                    CIFSContext origin_ctx = handle.getTransportContext();

                    for ( int i = 0; i < sids.length; i++ ) {
                        sids[ i ] = new SID(rpc.sids.sids[ i ].sid, 0, null, null, false);
                        sids[ i ].origin_server = origin_server;
                        sids[ i ].origin_ctx = origin_ctx;
                    }
                    if ( sids.length > 0 && ( flags & SID.SID_FLAG_RESOLVE_SIDS ) != 0 ) {
                        resolveSids(origin_ctx, origin_server, sids);
                    }
                    return sids;
                }
                finally {
                    if ( aliasHandle != null ) {
                        aliasHandle.close();
                    }
                }
            }
            catch ( IOException e ) {
                throw new CIFSException("Failed to get group member SIDs", e);
            }
        }

    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SidResolver#getLocalGroupsMap(jcifs.CIFSContext, jcifs.smb.SID, int)
     */
    @Override
    public Map<SID, ArrayList<SID>> getLocalGroupsMap ( CIFSContext tc, String authorityServerName, int flags ) throws CIFSException {
        SID domSid = tc.getSIDResolver().getServerSid(tc, authorityServerName);
        synchronized ( this.sidCache ) {
            try ( DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + authorityServerName + "[\\PIPE\\samr]", tc) ) {
                samr.SamrSamArray sam = new samr.SamrSamArray();
                SamrPolicyHandle policyHandle = new SamrPolicyHandle(handle, authorityServerName, 0x02000000);
                SamrDomainHandle domainHandle = new SamrDomainHandle(handle, policyHandle, 0x02000000, domSid);
                MsrpcEnumerateAliasesInDomain rpc = new MsrpcEnumerateAliasesInDomain(domainHandle, 0xFFFF, sam);
                handle.sendrecv(rpc);
                if ( rpc.retval != 0 )
                    throw new SmbException(rpc.retval, false);

                Map<SID, ArrayList<SID>> map = new HashMap<>();

                for ( int ei = 0; ei < rpc.sam.count; ei++ ) {
                    samr.SamrSamEntry entry = rpc.sam.entries[ ei ];

                    SID[] mems = getGroupMemberSids(tc, authorityServerName, domSid, entry.idx, flags);
                    SID groupSid = new SID(domSid, entry.idx);
                    groupSid.type = SID.SID_TYPE_ALIAS;
                    groupSid.domainName = domSid.getDomainName();
                    groupSid.acctName = ( new UnicodeString(entry.name, false) ).toString();

                    for ( int mi = 0; mi < mems.length; mi++ ) {
                        ArrayList<SID> groups = map.get(mems[ mi ]);
                        if ( groups == null ) {
                            groups = new ArrayList<>();
                            map.put(mems[ mi ], groups);
                        }
                        if ( !groups.contains(groupSid) )
                            groups.add(groupSid);
                    }
                }

                return map;
            }
            catch ( IOException e ) {
                throw new CIFSException("Failed to resolve groups", e);
            }
        }
    }
}
