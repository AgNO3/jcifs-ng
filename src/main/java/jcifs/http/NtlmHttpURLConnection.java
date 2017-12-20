/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.http;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.GeneralSecurityException;
import java.security.Permission;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.RuntimeCIFSException;
import jcifs.ntlmssp.NtlmFlags;
import jcifs.ntlmssp.NtlmMessage;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.smb.NtlmPasswordAuthentication;


/**
 * Wraps an <code>HttpURLConnection</code> to provide NTLM authentication
 * services.
 *
 * Please read <a href="../../../httpclient.html">Using jCIFS NTLM Authentication for HTTP Connections</a>.
 * 
 * Warning: Do not use this if there is a chance that you might have multiple connections (even plain
 * HttpURLConnections, for the complete JRE) to the same host with different or mixed anonymous/authenticated
 * credentials. Authenticated connections can/will be reused.
 * 
 * @deprecated This is broken by design, even a possible vulnerability. Deprecation is conditional on whether future JDK
 *             versions will allow to do this safely.
 */
@Deprecated
public class NtlmHttpURLConnection extends HttpURLConnection {

    private static final Logger log = LoggerFactory.getLogger(NtlmHttpURLConnection.class);
    private static final int MAX_REDIRECTS = Integer.parseInt(System.getProperty("http.maxRedirects", "20"));

    private HttpURLConnection connection;

    private Map<String, List<String>> requestProperties;

    private Map<String, List<String>> headerFields;

    private ByteArrayOutputStream cachedOutput;

    private String authProperty;

    private String authMethod;

    private boolean handshakeComplete;

    private CIFSContext transportContext;


    /**
     * 
     * @param connection
     *            connection to wrap
     * @param tc
     *            context to use
     */
    public NtlmHttpURLConnection ( HttpURLConnection connection, CIFSContext tc ) {
        super(connection.getURL());
        this.connection = connection;
        this.transportContext = tc;
        this.requestProperties = new HashMap<>();
        copySettings();
    }


    /**
     * 
     */
    private final void copySettings () {
        try {
            this.setRequestMethod(this.connection.getRequestMethod());
        }
        catch ( ProtocolException e ) {
            throw new RuntimeCIFSException("Failed to set request method", e);
        }
        this.headerFields = null;
        for ( Entry<String, List<String>> property : this.connection.getRequestProperties().entrySet() ) {
            String key = property.getKey();
            StringBuffer value = new StringBuffer();
            Iterator<String> values = property.getValue().iterator();
            while ( values.hasNext() ) {
                value.append(values.next());
                if ( values.hasNext() )
                    value.append(", ");
            }
            this.setRequestProperty(key, value.toString());
        }

        this.setAllowUserInteraction(this.connection.getAllowUserInteraction());
        this.setDoInput(this.connection.getDoInput());
        this.setDoOutput(this.connection.getDoOutput());
        this.setIfModifiedSince(this.connection.getIfModifiedSince());
        this.setUseCaches(this.connection.getUseCaches());
        this.setReadTimeout(this.connection.getReadTimeout());
        this.setConnectTimeout(this.connection.getConnectTimeout());
        this.setInstanceFollowRedirects(this.connection.getInstanceFollowRedirects());
    }


    @Override
    public void connect () throws IOException {
        if ( this.connected )
            return;
        this.connection.connect();
        this.connected = true;
    }


    private void handshake () {
        if ( this.handshakeComplete )
            return;
        try {
            doHandshake();
        }
        catch (
            IOException |
            GeneralSecurityException e ) {
            throw new RuntimeCIFSException("NTLM handshake failed", e);
        }
        this.handshakeComplete = true;
    }


    @Override
    public URL getURL () {
        return this.connection.getURL();
    }


    @Override
    public int getContentLength () {
        handshake();
        return this.connection.getContentLength();
    }


    @Override
    public String getContentType () {
        handshake();
        return this.connection.getContentType();
    }


    @Override
    public String getContentEncoding () {
        handshake();
        return this.connection.getContentEncoding();
    }


    @Override
    public long getExpiration () {
        handshake();
        return this.connection.getExpiration();
    }


    @Override
    public long getDate () {
        handshake();
        return this.connection.getDate();
    }


    @Override
    public long getLastModified () {
        handshake();
        return this.connection.getLastModified();
    }


    @Override
    public String getHeaderField ( String header ) {
        handshake();
        return this.connection.getHeaderField(header);
    }


    private Map<String, List<String>> getHeaderFields0 () {
        if ( this.headerFields != null )
            return this.headerFields;
        Map<String, List<String>> map = new HashMap<>();
        String key = this.connection.getHeaderFieldKey(0);
        String value = this.connection.getHeaderField(0);
        for ( int i = 1; key != null || value != null; i++ ) {
            List<String> values = map.get(key);
            if ( values == null ) {
                values = new ArrayList<>();
                map.put(key, values);
            }
            values.add(value);
            key = this.connection.getHeaderFieldKey(i);
            value = this.connection.getHeaderField(i);
        }
        for ( Entry<String, List<String>> entry : map.entrySet() ) {
            entry.setValue(Collections.unmodifiableList(entry.getValue()));
        }
        return ( this.headerFields = Collections.unmodifiableMap(map) );
    }


    @Override
    public Map<String, List<String>> getHeaderFields () {
        if ( this.headerFields != null )
            return this.headerFields;
        handshake();
        return getHeaderFields0();
    }


    @Override
    public int getHeaderFieldInt ( String header, int def ) {
        handshake();
        return this.connection.getHeaderFieldInt(header, def);
    }


    @Override
    public long getHeaderFieldDate ( String header, long def ) {
        handshake();
        return this.connection.getHeaderFieldDate(header, def);
    }


    @Override
    public String getHeaderFieldKey ( int index ) {
        handshake();
        return this.connection.getHeaderFieldKey(index);
    }


    @Override
    public String getHeaderField ( int index ) {
        handshake();
        return this.connection.getHeaderField(index);
    }


    @Override
    public Object getContent () throws IOException {
        handshake();
        return this.connection.getContent();
    }


    @Override
    public Object getContent ( Class[] classes ) throws IOException {
        handshake();
        return this.connection.getContent(classes);
    }


    @Override
    public Permission getPermission () throws IOException {
        return this.connection.getPermission();
    }


    @Override
    public InputStream getInputStream () throws IOException {
        handshake();
        return this.connection.getInputStream();
    }


    @SuppressWarnings ( "resource" )
    @Override
    public OutputStream getOutputStream () throws IOException {
        connect();
        OutputStream output = this.connection.getOutputStream();
        this.cachedOutput = new ByteArrayOutputStream();
        return new CacheStream(output, this.cachedOutput);
    }


    @Override
    public String toString () {
        return this.connection.toString();
    }


    @Override
    public void setDoInput ( boolean doInput ) {
        this.connection.setDoInput(doInput);
        this.doInput = doInput;
    }


    @Override
    public boolean getDoInput () {
        return this.connection.getDoInput();
    }


    @Override
    public void setDoOutput ( boolean doOutput ) {
        this.connection.setDoOutput(doOutput);
        this.doOutput = doOutput;
    }


    @Override
    public boolean getDoOutput () {
        return this.connection.getDoOutput();
    }


    @Override
    public void setAllowUserInteraction ( boolean allowUserInteraction ) {
        this.connection.setAllowUserInteraction(allowUserInteraction);
        this.allowUserInteraction = allowUserInteraction;
    }


    @Override
    public boolean getAllowUserInteraction () {
        return this.connection.getAllowUserInteraction();
    }


    @Override
    public void setUseCaches ( boolean useCaches ) {
        this.connection.setUseCaches(useCaches);
        this.useCaches = useCaches;
    }


    @Override
    public boolean getUseCaches () {
        return this.connection.getUseCaches();
    }


    @Override
    public void setIfModifiedSince ( long ifModifiedSince ) {
        this.connection.setIfModifiedSince(ifModifiedSince);
        this.ifModifiedSince = ifModifiedSince;
    }


    @Override
    public long getIfModifiedSince () {
        return this.connection.getIfModifiedSince();
    }


    @Override
    public boolean getDefaultUseCaches () {
        return this.connection.getDefaultUseCaches();
    }


    @Override
    public void setDefaultUseCaches ( boolean defaultUseCaches ) {
        this.connection.setDefaultUseCaches(defaultUseCaches);
    }


    @Override
    public int getConnectTimeout () {
        return this.connection.getConnectTimeout();
    }


    @Override
    public void setConnectTimeout ( int timeout ) {
        this.connection.setConnectTimeout(timeout);
    }


    @Override
    public int getReadTimeout () {
        return this.connection.getReadTimeout();
    }


    @Override
    public void setReadTimeout ( int timeout ) {
        this.connection.setReadTimeout(timeout);
    }


    @Override
    public void setRequestProperty ( String key, String value ) {
        if ( key == null )
            throw new NullPointerException();
        List<String> values = new ArrayList<>();
        values.add(value);
        boolean found = false;

        for ( Entry<String, List<String>> entry : this.requestProperties.entrySet() ) {
            if ( key.equalsIgnoreCase(entry.getKey()) ) {
                entry.setValue(values);
                found = true;
                break;
            }
        }
        if ( !found )
            this.requestProperties.put(key, values);
        this.connection.setRequestProperty(key, value);
    }


    @Override
    public void addRequestProperty ( String key, String value ) {
        if ( key == null )
            throw new NullPointerException();
        List<String> values = null;

        for ( Entry<String, List<String>> entry : this.requestProperties.entrySet() ) {
            if ( key.equalsIgnoreCase(entry.getKey()) ) {
                values = entry.getValue();
                values.add(value);
                break;
            }
        }
        if ( values == null ) {
            values = new ArrayList<>();
            values.add(value);
            this.requestProperties.put(key, values);
        }
        // 1.3-compatible.
        StringBuffer buffer = new StringBuffer();
        Iterator<String> propertyValues = values.iterator();
        while ( propertyValues.hasNext() ) {
            buffer.append(propertyValues.next());
            if ( propertyValues.hasNext() ) {
                buffer.append(", ");
            }
        }
        this.connection.setRequestProperty(key, buffer.toString());
    }


    @Override
    public String getRequestProperty ( String key ) {
        return this.connection.getRequestProperty(key);
    }


    @Override
    public Map<String, List<String>> getRequestProperties () {
        Map<String, List<String>> map = new HashMap<>();
        for ( Entry<String, List<String>> entry : this.requestProperties.entrySet() ) {
            map.put(entry.getKey(), Collections.unmodifiableList(entry.getValue()));
        }
        return Collections.unmodifiableMap(map);
    }


    @Override
    public void setInstanceFollowRedirects ( boolean instanceFollowRedirects ) {
        this.connection.setInstanceFollowRedirects(instanceFollowRedirects);
    }


    @Override
    public boolean getInstanceFollowRedirects () {
        return this.connection.getInstanceFollowRedirects();
    }


    @Override
    public void setRequestMethod ( String requestMethod ) throws ProtocolException {
        this.connection.setRequestMethod(requestMethod);
        this.method = requestMethod;
    }


    @Override
    public String getRequestMethod () {
        return this.connection.getRequestMethod();
    }


    @Override
    public int getResponseCode () throws IOException {
        handshake();
        return this.connection.getResponseCode();
    }


    @Override
    public String getResponseMessage () throws IOException {
        handshake();
        return this.connection.getResponseMessage();
    }


    @Override
    public void disconnect () {
        this.connection.disconnect();
        this.handshakeComplete = false;
        this.connected = false;
    }


    @Override
    public boolean usingProxy () {
        return this.connection.usingProxy();
    }


    @Override
    public InputStream getErrorStream () {
        handshake();
        return this.connection.getErrorStream();
    }


    private int parseResponseCode () throws IOException {
        try {
            String response = this.connection.getHeaderField(0);
            int index = response.indexOf(' ');
            while ( response.charAt(index) == ' ' )
                index++;
            return Integer.parseInt(response.substring(index, index + 3));
        }
        catch ( Exception ex ) {
            throw new IOException(ex.getMessage());
        }
    }


    private void doHandshake () throws IOException, GeneralSecurityException {
        connect();
        try {
            int response = parseResponseCode();
            if ( response != HTTP_UNAUTHORIZED && response != HTTP_PROXY_AUTH ) {
                return;
            }
            NtlmMessage type1 = attemptNegotiation(response);
            if ( type1 == null )
                return; // no NTLM
            int attempt = 0;
            while ( attempt < MAX_REDIRECTS ) {
                this.connection.setRequestProperty(this.authProperty, this.authMethod + ' ' + Base64.toBase64String(type1.toByteArray()));
                this.connection.connect(); // send type 1
                response = parseResponseCode();
                if ( response != HTTP_UNAUTHORIZED && response != HTTP_PROXY_AUTH ) {
                    return;
                }
                NtlmMessage type3 = attemptNegotiation(response);
                if ( type3 == null )
                    return;
                this.connection.setRequestProperty(this.authProperty, this.authMethod + ' ' + Base64.toBase64String(type3.toByteArray()));
                this.connection.connect(); // send type 3
                if ( this.cachedOutput != null && this.doOutput ) {
                    @SuppressWarnings ( "resource" )
                    OutputStream output = this.connection.getOutputStream();
                    this.cachedOutput.writeTo(output);
                    output.flush();
                }
                response = parseResponseCode();
                if ( response != HTTP_UNAUTHORIZED && response != HTTP_PROXY_AUTH ) {
                    return;
                }
                attempt++;
                if ( this.allowUserInteraction && attempt < MAX_REDIRECTS ) {
                    reconnect();
                }
                else {
                    break;
                }
            }
            throw new IOException("Unable to negotiate NTLM authentication.");
        }
        finally {
            this.cachedOutput = null;
        }
    }


    private NtlmMessage attemptNegotiation ( int response ) throws IOException, GeneralSecurityException {
        this.authProperty = null;
        this.authMethod = null;
        try ( InputStream errorStream = this.connection.getErrorStream() ) {
            if ( errorStream != null && errorStream.available() != 0 ) {
                byte[] buf = new byte[1024];
                while ( ( errorStream.read(buf, 0, 1024) ) != -1 );
            }
            String authHeader;
            if ( response == HTTP_UNAUTHORIZED ) {
                authHeader = "WWW-Authenticate";
                this.authProperty = "Authorization";
            }
            else {
                authHeader = "Proxy-Authenticate";
                this.authProperty = "Proxy-Authorization";
            }
            String authorization = null;
            List<String> methods = getHeaderFields0().get(authHeader);
            if ( methods == null )
                return null;
            Iterator<String> iterator = methods.iterator();
            while ( iterator.hasNext() ) {
                String currentAuthMethod = iterator.next();
                if ( currentAuthMethod.startsWith("NTLM") ) {
                    if ( currentAuthMethod.length() == 4 ) {
                        this.authMethod = "NTLM";
                        break;
                    }
                    if ( currentAuthMethod.indexOf(' ') != 4 )
                        continue;
                    this.authMethod = "NTLM";
                    authorization = currentAuthMethod.substring(5).trim();
                    break;
                }
                else if ( currentAuthMethod.startsWith("Negotiate") ) {
                    if ( currentAuthMethod.length() == 9 ) {
                        this.authMethod = "Negotiate";
                        break;
                    }
                    if ( currentAuthMethod.indexOf(' ') != 9 )
                        continue;
                    this.authMethod = "Negotiate";
                    authorization = currentAuthMethod.substring(10).trim();
                    break;
                }
            }
            if ( this.authMethod == null )
                return null;
            NtlmMessage message = ( authorization != null ) ? new Type2Message(Base64.decode(authorization)) : null;
            reconnect();
            if ( message == null ) {
                message = new Type1Message(this.transportContext);
                if ( this.transportContext.getConfig().getLanManCompatibility() > 2 ) {
                    message.setFlag(NtlmFlags.NTLMSSP_REQUEST_TARGET, true);
                }
            }
            else if ( this.transportContext.getCredentials() instanceof NtlmPasswordAuthentication ) {
                NtlmPasswordAuthentication npa = (NtlmPasswordAuthentication) this.transportContext.getCredentials();
                String domain = npa.getUserDomain();
                String user = !npa.isAnonymous() ? npa.getUsername() : null;
                String password = npa.getPassword();
                String userInfo = this.url.getUserInfo();
                if ( userInfo != null ) {
                    userInfo = URLDecoder.decode(userInfo, "UTF-8");
                    int index = userInfo.indexOf(':');
                    user = ( index != -1 ) ? userInfo.substring(0, index) : userInfo;
                    if ( index != -1 )
                        password = userInfo.substring(index + 1);
                    index = user.indexOf('\\');
                    if ( index == -1 )
                        index = user.indexOf('/');
                    domain = ( index != -1 ) ? user.substring(0, index) : domain;
                    user = ( index != -1 ) ? user.substring(index + 1) : user;
                }
                if ( user == null ) {
                    if ( !this.allowUserInteraction )
                        return null;
                    try {
                        URL u = getURL();
                        String protocol = u.getProtocol();
                        int port = u.getPort();
                        if ( port == -1 ) {
                            port = "https".equalsIgnoreCase(protocol) ? 443 : 80;
                        }
                        PasswordAuthentication auth = Authenticator.requestPasswordAuthentication(null, port, protocol, "", this.authMethod);
                        if ( auth == null )
                            return null;
                        user = auth.getUserName();
                        password = new String(auth.getPassword());
                    }
                    catch ( Exception ex ) {
                        log.debug("Interactive authentication failed", ex);
                    }
                }
                Type2Message type2 = (Type2Message) message;
                message = new Type3Message(
                    this.transportContext,
                    type2,
                    null,
                    password,
                    domain,
                    user,
                    this.transportContext.getNameServiceClient().getLocalHost().getHostName(),
                    0);
            }
            return message;
        }
    }


    private void reconnect () throws IOException {
        int readTimeout = getReadTimeout();
        int connectTimeout = getConnectTimeout();

        HostnameVerifier hv = null;
        SSLSocketFactory ssf = null;
        if ( this.connection instanceof HttpsURLConnection ) {
            hv = ( (HttpsURLConnection) this.connection ).getHostnameVerifier();
            ssf = ( (HttpsURLConnection) this.connection ).getSSLSocketFactory();
        }

        this.connection = (HttpURLConnection) this.connection.getURL().openConnection();

        if ( this.connection instanceof HttpsURLConnection ) {
            if ( hv != null ) {
                ( (HttpsURLConnection) this.connection ).setHostnameVerifier(hv);
            }
            if ( ssf != null ) {
                ( (HttpsURLConnection) this.connection ).setSSLSocketFactory(ssf);
            }
        }

        this.connection.setRequestMethod(this.method);
        this.headerFields = null;
        for ( Entry<String, List<String>> property : this.requestProperties.entrySet() ) {
            String key = property.getKey();
            StringBuffer value = new StringBuffer();
            Iterator<String> values = property.getValue().iterator();
            while ( values.hasNext() ) {
                value.append(values.next());
                if ( values.hasNext() )
                    value.append(", ");
            }
            this.connection.setRequestProperty(key, value.toString());
        }

        this.connection.setAllowUserInteraction(this.allowUserInteraction);
        this.connection.setDoInput(this.doInput);
        this.connection.setDoOutput(this.doOutput);
        this.connection.setIfModifiedSince(this.ifModifiedSince);
        this.connection.setInstanceFollowRedirects(this.instanceFollowRedirects);
        this.connection.setUseCaches(this.useCaches);
        this.connection.setReadTimeout(readTimeout);
        this.connection.setConnectTimeout(connectTimeout);
    }

    private static class CacheStream extends OutputStream {

        private final OutputStream stream;

        private final OutputStream collector;


        public CacheStream ( OutputStream stream, OutputStream collector ) {
            this.stream = stream;
            this.collector = collector;
        }


        @Override
        public void close () throws IOException {
            this.stream.close();
            this.collector.close();
        }


        @Override
        public void flush () throws IOException {
            this.stream.flush();
            this.collector.flush();
        }


        @Override
        public void write ( byte[] b ) throws IOException {
            this.stream.write(b);
            this.collector.write(b);
        }


        @Override
        public void write ( byte[] b, int off, int len ) throws IOException {
            this.stream.write(b, off, len);
            this.collector.write(b, off, len);
        }


        @Override
        public void write ( int b ) throws IOException {
            this.stream.write(b);
            this.collector.write(b);
        }

    }

}
