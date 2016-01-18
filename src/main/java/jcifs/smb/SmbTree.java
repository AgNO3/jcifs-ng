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

package jcifs.smb;


import org.apache.log4j.Logger;

import jcifs.SmbConstants;


class SmbTree {

    private static final Logger log = Logger.getLogger(SmbTree.class);

    private static int tree_conn_counter;

    /*
     * 0 - not connected
     * 1 - connecting
     * 2 - connected
     * 3 - disconnecting
     */
    int connectionState;
    int tid;

    String share;
    String service = "?????";
    String service0;
    SmbSession session;
    boolean inDfs, inDomainDfs;
    int tree_num; // used by SmbFile.isOpen


    SmbTree ( SmbSession session, String share, String service ) {
        this.session = session;
        this.share = share.toUpperCase();
        if ( service != null && service.startsWith("??") == false ) {
            this.service = service;
        }
        this.service0 = this.service;
        this.connectionState = 0;
    }


    boolean matches ( String shr, String servc ) {
        return this.share.equalsIgnoreCase(shr) && ( servc == null || servc.startsWith("??") || this.service.equalsIgnoreCase(servc) );
    }


    @Override
    public boolean equals ( Object obj ) {
        if ( obj instanceof SmbTree ) {
            SmbTree tree = (SmbTree) obj;
            return matches(tree.share, tree.service);
        }
        return false;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode () {
        return this.share.hashCode() + 7 * this.service.hashCode();
    }


    void send ( ServerMessageBlock request, ServerMessageBlock response ) throws SmbException {
        synchronized ( this.session.transport() ) {
            if ( response != null ) {
                response.received = false;
            }
            treeConnect(request, response);
            if ( request == null || ( response != null && response.received ) ) {
                return;
            }
            if ( !this.service.equals("A:") ) {
                switch ( request.command ) {
                case ServerMessageBlock.SMB_COM_OPEN_ANDX:
                case ServerMessageBlock.SMB_COM_NT_CREATE_ANDX:
                case ServerMessageBlock.SMB_COM_READ_ANDX:
                case ServerMessageBlock.SMB_COM_WRITE_ANDX:
                case ServerMessageBlock.SMB_COM_CLOSE:
                case ServerMessageBlock.SMB_COM_TREE_DISCONNECT:
                    break;
                case ServerMessageBlock.SMB_COM_TRANSACTION:
                case ServerMessageBlock.SMB_COM_TRANSACTION2:
                    switch ( ( (SmbComTransaction) request ).subCommand & 0xFF ) {
                    case SmbComTransaction.NET_SHARE_ENUM:
                    case SmbComTransaction.NET_SERVER_ENUM2:
                    case SmbComTransaction.NET_SERVER_ENUM3:
                    case SmbComTransaction.TRANS_PEEK_NAMED_PIPE:
                    case SmbComTransaction.TRANS_WAIT_NAMED_PIPE:
                    case SmbComTransaction.TRANS_CALL_NAMED_PIPE:
                    case SmbComTransaction.TRANS_TRANSACT_NAMED_PIPE:
                    case SmbComTransaction.TRANS2_GET_DFS_REFERRAL:
                        break;
                    default:
                        throw new SmbException("Invalid operation for " + this.service + " service");
                    }
                    break;
                default:
                    throw new SmbException("Invalid operation for " + this.service + " service" + request);
                }
            }
            request.tid = this.tid;
            if ( this.inDfs && !this.service.equals("IPC") && request.path != null && request.path.length() > 0 ) {
                /*
                 * When DFS is in action all request paths are
                 * full UNC paths minus the first backslash like
                 * \server\share\path\to\file
                 * as opposed to normally
                 * \path\to\file
                 */
                request.flags2 = SmbConstants.FLAGS2_RESOLVE_PATHS_IN_DFS;
                request.path = '\\' + this.session.transport().tconHostName + '\\' + this.share + request.path;
            }
            try {
                this.session.send(request, response);
            }
            catch ( SmbException se ) {
                if ( se.getNtStatus() == NtStatus.NT_STATUS_NETWORK_NAME_DELETED ) {
                    /*
                     * Someone removed the share while we were
                     * connected. Bastards! Disconnect this tree
                     * so that it reconnects cleanly should the share
                     * reappear in this client's lifetime.
                     */
                    treeDisconnect(true);
                }
                throw se;
            }
        }
    }


    void treeConnect ( ServerMessageBlock andx, ServerMessageBlock andxResponse ) throws SmbException {

        synchronized ( this.session.transport() ) {
            String unc;

            while ( this.connectionState != 0 ) {
                if ( this.connectionState == 2 || this.connectionState == 3 ) // connected or disconnecting
                    return;
                try {
                    this.session.getTransport().wait();
                }
                catch ( InterruptedException ie ) {
                    throw new SmbException(ie.getMessage(), ie);
                }
            }
            this.connectionState = 1; // trying ...

            try {
                /*
                 * The hostname to use in the path is only known for
                 * sure if the NetBIOS session has been successfully
                 * established.
                 */

                this.session.getTransport().connect();

                unc = "\\\\" + this.session.getTransport().tconHostName + '\\' + this.share;

                /*
                 * IBM iSeries doesn't like specifying a service. Always reset
                 * the service to whatever was determined in the constructor.
                 */
                this.service = this.service0;

                /*
                 * Tree Connect And X Request / Response
                 */

                if ( log.isTraceEnabled() ) {
                    log.trace("treeConnect: unc=" + unc + ",service=" + this.service);
                }

                SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(this.session.getConfig(), andxResponse);
                SmbComTreeConnectAndX request = new SmbComTreeConnectAndX(this.session, unc, this.service, andx);
                this.session.send(request, response);

                this.tid = response.tid;
                this.service = response.service;
                this.inDfs = response.shareIsInDfs;
                this.tree_num = tree_conn_counter++;

                this.connectionState = 2; // connected
            }
            catch ( SmbException se ) {
                treeDisconnect(true);
                this.connectionState = 0;
                throw se;
            }
        }
    }


    void treeDisconnect ( boolean inError ) {
        synchronized ( this.session.transport() ) {

            if ( this.connectionState != 2 ) // not-connected
                return;
            this.connectionState = 3; // disconnecting

            if ( !inError && this.tid != 0 ) {
                try {
                    send(new SmbComTreeDisconnect(this.session.getConfig()), null);
                }
                catch ( SmbException se ) {
                    log.error("SmbComTreeDisconnect failed", se);
                }
            }
            this.inDfs = false;
            this.inDomainDfs = false;

            this.connectionState = 0;

            this.session.getTransport().notifyAll();
        }
    }


    @Override
    public String toString () {
        return "SmbTree[share=" + this.share + ",service=" + this.service + ",tid=" + this.tid + ",inDfs=" + this.inDfs + ",inDomainDfs="
                + this.inDomainDfs + ",connectionState=" + this.connectionState + "]";
    }
}
