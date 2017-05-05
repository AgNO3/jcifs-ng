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


import java.net.InetAddress;
import java.net.UnknownHostException;

import jcifs.Address;
import jcifs.NameServiceClient;
import jcifs.NetbiosAddress;
import jcifs.NetbiosName;


/**
 * @author mbechler
 *
 */
public class DelegatingNameServiceClient implements NameServiceClient {

    private NameServiceClient nscl;


    /**
     * @param nscl
     * 
     */
    public DelegatingNameServiceClient ( NameServiceClient nscl ) {
        this.nscl = nscl;
    }


    @Override
    public NetbiosName getUnknownName () {
        return this.nscl.getUnknownName();
    }


    @Override
    public NetbiosAddress[] getNodeStatus ( NetbiosAddress nbtAddress ) throws UnknownHostException {
        return this.nscl.getNodeStatus(nbtAddress);
    }


    @Override
    public NetbiosAddress getNbtByName ( String host ) throws UnknownHostException {
        return this.nscl.getNbtByName(host);
    }


    @Override
    public NetbiosAddress getNbtByName ( String host, int type, String scope ) throws UnknownHostException {
        return this.nscl.getNbtByName(host, type, scope);
    }


    @Override
    public NetbiosAddress getNbtByName ( String host, int type, String scope, InetAddress svr ) throws UnknownHostException {
        return this.nscl.getNbtByName(host, type, scope, svr);
    }


    @Override
    public NetbiosAddress[] getNbtAllByName ( String host, int type, String scope, InetAddress svr ) throws UnknownHostException {
        return this.nscl.getNbtAllByName(host, type, scope, svr);
    }


    @Override
    public NetbiosAddress[] getNbtAllByAddress ( String host ) throws UnknownHostException {
        return this.nscl.getNbtAllByAddress(host);
    }


    @Override
    public NetbiosAddress[] getNbtAllByAddress ( String host, int type, String scope ) throws UnknownHostException {
        return this.nscl.getNbtAllByAddress(host, type, scope);
    }


    @Override
    public NetbiosAddress[] getNbtAllByAddress ( NetbiosAddress addr ) throws UnknownHostException {
        return this.nscl.getNbtAllByAddress(addr);
    }


    @Override
    public NetbiosName getLocalName () {
        return this.nscl.getLocalName();
    }


    @Override
    public NetbiosAddress getLocalHost () {
        return this.nscl.getLocalHost();
    }


    @Override
    public Address getByName ( String hostname ) throws UnknownHostException {
        return this.nscl.getByName(hostname);
    }


    @Override
    public Address getByName ( String hostname, boolean possibleNTDomainOrWorkgroup ) throws UnknownHostException {
        return this.nscl.getByName(hostname, possibleNTDomainOrWorkgroup);
    }


    @Override
    public Address[] getAllByName ( String hostname, boolean possibleNTDomainOrWorkgroup ) throws UnknownHostException {
        return this.nscl.getAllByName(hostname, possibleNTDomainOrWorkgroup);
    }

}
