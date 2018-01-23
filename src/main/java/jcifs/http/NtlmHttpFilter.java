/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Jason Pugsley" <jcifs at samba dot org>
 *                   "skeetz" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
 *                   and Marcel, Thomas, ...
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

package jcifs.http;


import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.Properties;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Config;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.netbios.UniAddress;
import jcifs.smb.NtStatus;
import jcifs.smb.NtlmChallenge;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbException;
import jcifs.smb.SmbSessionInternal;
import jcifs.smb.SmbTransportInternal;


/**
 * This servlet Filter can be used to negotiate password hashes with
 * MSIE clients using NTLM SSP. This is similar to <tt>Authentication:
 * BASIC</tt> but weakly encrypted and without requiring the user to re-supply
 * authentication credentials.
 * <p>
 * Read <a href="../../../ntlmhttpauth.html">jCIFS NTLM HTTP Authentication and the Network Explorer Servlet</a> for
 * complete details.
 * 
 * @deprecated NTLMv1 only
 */
@Deprecated
public class NtlmHttpFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(NtlmHttpFilter.class);

    private String defaultDomain;
    private String domainController;
    private boolean loadBalance;
    private boolean enableBasic;
    private boolean insecureBasic;
    private String realm;

    private CIFSContext transportContext;
    private Address[] dcList = null;
    private long dcListExpiration;

    private int netbiosLookupRespLimit = 3;
    private long netbiosCacheTimeout = 60 * 60 * 10;
    private static int dcListCounter;


    @Override
    public void init ( FilterConfig filterConfig ) throws ServletException {
        String name;

        Properties p = new Properties();
        /*
         * Set jcifs properties we know we want; soTimeout and cachePolicy to 30min.
         */
        p.setProperty("jcifs.smb.client.soTimeout", "1800000");
        p.setProperty("jcifs.netbios.cachePolicy", "1200");
        /*
         * The Filter can only work with NTLMv1 as it uses a man-in-the-middle
         * technique that NTLMv2 specifically thwarts. A real NTLM Filter would
         * need to do a NETLOGON RPC that JCIFS will likely never implement
         * because it requires a lot of extra crypto not used by CIFS.
         */
        p.setProperty("jcifs.smb.lmCompatibility", "0");
        p.setProperty("jcifs.smb.client.useExtendedSecurity", "false");

        Enumeration<String> e = filterConfig.getInitParameterNames();
        while ( e.hasMoreElements() ) {
            name = e.nextElement();
            if ( name.startsWith("jcifs.") ) {
                p.setProperty(name, filterConfig.getInitParameter(name));
            }
        }

        try {
            this.defaultDomain = p.getProperty("jcifs.smb.client.domain");
            this.domainController = p.getProperty("jcifs.http.domainController");
            if ( this.domainController == null ) {
                this.domainController = this.defaultDomain;
                this.loadBalance = Config.getBoolean(p, "jcifs.http.loadBalance", true);
            }
            this.enableBasic = Boolean.valueOf(p.getProperty("jcifs.http.enableBasic")).booleanValue();
            this.insecureBasic = Boolean.valueOf(p.getProperty("jcifs.http.insecureBasic")).booleanValue();
            this.realm = p.getProperty("jcifs.http.basicRealm");
            this.netbiosLookupRespLimit = Config.getInt(p, "jcifs.netbios.lookupRespLimit", 3);
            this.netbiosCacheTimeout = Config.getInt(p, "jcifs.netbios.cachePolicy", 60 * 10) * 60; /* 10 hours */

            if ( this.realm == null )
                this.realm = "jCIFS";

            this.transportContext = new BaseContext(new PropertyConfiguration(p));
        }
        catch ( CIFSException ex ) {
            throw new ServletException("Failed to initialize CIFS context");
        }
    }


    @Override
    public void destroy () {}


    /**
     * This method simply calls <tt>negotiate( req, resp, false )</tt>
     * and then <tt>chain.doFilter</tt>. You can override and call
     * negotiate manually to achive a variety of different behavior.
     */
    @Override
    public void doFilter ( ServletRequest request, ServletResponse response, FilterChain chain ) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        NtlmPasswordAuthentication ntlm;

        if ( ( ntlm = negotiate(req, resp, false) ) == null ) {
            return;
        }

        chain.doFilter(new NtlmHttpServletRequest(req, ntlm), response);
    }


    /**
     * Negotiate password hashes with MSIE clients using NTLM SSP
     * 
     * @param req
     *            The servlet request
     * @param resp
     *            The servlet response
     * @param skipAuthentication
     *            If true the negotiation is only done if it is
     *            initiated by the client (MSIE post requests after successful NTLM SSP
     *            authentication). If false and the user has not been authenticated yet
     *            the client will be forced to send an authentication (server sends
     *            HttpServletResponse.SC_UNAUTHORIZED).
     * @return True if the negotiation is complete, otherwise false
     * @throws ServletException
     */
    protected NtlmPasswordAuthentication negotiate ( HttpServletRequest req, HttpServletResponse resp, boolean skipAuthentication )
            throws IOException, ServletException {
        Address dc;
        String msg;
        NtlmPasswordAuthentication ntlm = null;
        msg = req.getHeader("Authorization");
        boolean offerBasic = this.enableBasic && ( this.insecureBasic || req.isSecure() );

        if ( msg != null && ( msg.startsWith("NTLM ") || ( offerBasic && msg.startsWith("Basic ") ) ) ) {
            if ( msg.startsWith("NTLM ") ) {
                HttpSession ssn = req.getSession();
                byte[] challenge;

                if ( this.loadBalance ) {
                    NtlmChallenge chal = (NtlmChallenge) ssn.getAttribute("NtlmHttpChal");
                    if ( chal == null ) {
                        chal = getChallengeForDomain(this.defaultDomain);
                        ssn.setAttribute("NtlmHttpChal", chal);
                    }
                    dc = chal.dc;
                    challenge = chal.challenge;
                }
                else {
                    dc = getTransportContext().getNameServiceClient().getByName(this.domainController, true);
                    challenge = getTransportContext().getTransportPool().getChallenge(getTransportContext(), dc);
                }

                if ( ( ntlm = NtlmSsp.authenticate(getTransportContext(), req, resp, challenge) ) == null ) {
                    return null;
                }
                /* negotiation complete, remove the challenge object */
                ssn.removeAttribute("NtlmHttpChal");
            }
            else {
                String auth = new String(Base64.decode(msg.substring(6)), "US-ASCII");
                int index = auth.indexOf(':');
                String user = ( index != -1 ) ? auth.substring(0, index) : auth;
                String password = ( index != -1 ) ? auth.substring(index + 1) : "";
                index = user.indexOf('\\');
                if ( index == -1 )
                    index = user.indexOf('/');
                String domain = ( index != -1 ) ? user.substring(0, index) : this.defaultDomain;
                user = ( index != -1 ) ? user.substring(index + 1) : user;
                ntlm = new NtlmPasswordAuthentication(getTransportContext(), domain, user, password);
                dc = getTransportContext().getNameServiceClient().getByName(this.domainController, true);
            }
            try {
                getTransportContext().getTransportPool().logon(getTransportContext(), dc);

                if ( log.isDebugEnabled() ) {
                    log.debug("NtlmHttpFilter: " + ntlm + " successfully authenticated against " + dc);
                }
            }
            catch ( SmbAuthException sae ) {
                log.warn("NtlmHttpFilter: " + ntlm.getName() + ": 0x" + jcifs.util.Hexdump.toHexString(sae.getNtStatus(), 8) + ": " + sae);
                if ( sae.getNtStatus() == NtStatus.NT_STATUS_ACCESS_VIOLATION ) {
                    /*
                     * Server challenge no longer valid for
                     * externally supplied password hashes.
                     */
                    HttpSession ssn = req.getSession(false);
                    if ( ssn != null ) {
                        ssn.removeAttribute("NtlmHttpAuth");
                    }
                }
                resp.setHeader("WWW-Authenticate", "NTLM");
                if ( offerBasic ) {
                    resp.addHeader("WWW-Authenticate", "Basic realm=\"" + this.realm + "\"");
                }
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                resp.setContentLength(0); /* Marcel Feb-15-2005 */
                resp.flushBuffer();
                return null;
            }
            req.getSession().setAttribute("NtlmHttpAuth", ntlm);
        }
        else {
            if ( !skipAuthentication ) {
                HttpSession ssn = req.getSession(false);
                if ( ssn == null || ( ntlm = (NtlmPasswordAuthentication) ssn.getAttribute("NtlmHttpAuth") ) == null ) {
                    resp.setHeader("WWW-Authenticate", "NTLM");
                    if ( offerBasic ) {
                        resp.addHeader("WWW-Authenticate", "Basic realm=\"" + this.realm + "\"");
                    }
                    resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    resp.setContentLength(0);
                    resp.flushBuffer();
                    return null;
                }
            }
        }

        return ntlm;
    }


    private synchronized NtlmChallenge getChallengeForDomain ( String domain ) throws UnknownHostException, ServletException {
        if ( domain == null ) {
            throw new ServletException("A domain was not specified");
        }
        long now = System.currentTimeMillis();
        int retry = 1;

        do {
            if ( this.dcListExpiration < now ) {
                Address[] list = getTransportContext().getNameServiceClient().getNbtAllByName(domain, 0x1C, null, null);
                this.dcListExpiration = now + this.netbiosCacheTimeout * 1000L;
                if ( list != null && list.length > 0 ) {
                    this.dcList = list;
                }
                else { /* keep using the old list */
                    this.dcListExpiration = now + 1000 * 60 * 15; /* 15 min */
                    log.warn("Failed to retrieve DC list from WINS");
                }
            }

            int max = Math.min(this.dcList.length, this.netbiosLookupRespLimit);
            for ( int j = 0; j < max; j++ ) {
                int i = dcListCounter++ % max;
                if ( this.dcList[ i ] != null ) {
                    try {
                        return interrogate(getTransportContext(), this.dcList[ i ]);
                    }
                    catch ( SmbException se ) {
                        log.warn("Failed validate DC: " + this.dcList[ i ], se);
                    }
                    this.dcList[ i ] = null;
                }
            }

            /*
             * No DCs found, for retieval of list by expiring it and retry.
             */
            this.dcListExpiration = 0;
        }
        while ( retry-- > 0 );

        this.dcListExpiration = now + 1000 * 60 * 15; /* 15 min */
        throw new UnknownHostException("Failed to negotiate with a suitable domain controller for " + domain);
    }


    private static NtlmChallenge interrogate ( CIFSContext tf, Address addr ) throws SmbException {
        UniAddress dc = new UniAddress(addr);
        try ( SmbTransportInternal trans = tf.getTransportPool()
                .getSmbTransport(tf, dc, 0, false, tf.hasDefaultCredentials() && tf.getConfig().isIpcSigningEnforced())
                .unwrap(SmbTransportInternal.class) ) {
            if ( !tf.hasDefaultCredentials() ) {
                trans.ensureConnected();
                log.warn(
                    "Default credentials (jcifs.smb.client.username/password)" + " not specified. SMB signing may not work propertly."
                            + "  Skipping DC interrogation.");
            }
            else {
                try ( SmbSessionInternal ssn = trans.getSmbSession(tf.withDefaultCredentials()).unwrap(SmbSessionInternal.class) ) {
                    ssn.treeConnectLogon();
                }
            }
            return new NtlmChallenge(trans.getServerEncryptionKey(), dc);
        }
        catch ( SmbException e ) {
            throw e;
        }
        catch ( IOException e ) {
            throw new SmbException("Connection failed", e);
        }
    }


    /**
     * @return
     */
    private CIFSContext getTransportContext () {
        return this.transportContext;
    }


    // Added by cgross to work with weblogic 6.1.
    /**
     * @param f
     */
    public void setFilterConfig ( FilterConfig f ) {
        try {
            init(f);
        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }


    /**
     * @return filter config
     */
    public FilterConfig getFilterConfig () {
        return null;
    }
}
