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
package jcifs.internal.smb2;


import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.smb.NtStatus;


/**
 * @author mbechler
 *
 */
public abstract class ServerMessageBlock2Response extends ServerMessageBlock2 implements CommonServerMessageBlockResponse {

    private boolean received;
    private boolean error;
    private Long expiration;

    private boolean verifyFailed;
    private Exception exception;
    private boolean asyncHandled;


    /**
     * @param config
     * @param command
     */
    public ServerMessageBlock2Response ( Configuration config, int command ) {
        super(config, command);
    }


    /**
     * @param config
     */
    public ServerMessageBlock2Response ( Configuration config ) {
        super(config);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockResponse#getNextResponse()
     */
    @Override
    public CommonServerMessageBlockResponse getNextResponse () {
        return (CommonServerMessageBlockResponse) getNext();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockResponse#prepare(jcifs.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public void prepare ( CommonServerMessageBlockRequest next ) {
        CommonServerMessageBlockResponse n = getNextResponse();
        if ( n != null ) {
            n.prepare(next);
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#reset()
     */
    @Override
    public void reset () {
        super.reset();
        this.received = false;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#received()
     */
    @Override
    public final void received () {
        if ( isAsync() && getStatus() == NtStatus.NT_STATUS_PENDING ) {
            synchronized ( this ) {
                notifyAll();
            }
            return;
        }
        this.received = true;
        synchronized ( this ) {
            notifyAll();
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#exception(java.lang.Exception)
     */
    @Override
    public final void exception ( Exception e ) {
        this.error = true;
        this.exception = e;
        this.received = true;
        synchronized ( this ) {
            notifyAll();
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#error()
     */
    @Override
    public final void error () {
        this.error = true;
        synchronized ( this ) {
            notifyAll();
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#clearReceived()
     */
    @Override
    public final void clearReceived () {
        this.received = false;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#isReceived()
     */
    @Override
    public final boolean isReceived () {
        return this.received;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#isError()
     */
    @Override
    public final boolean isError () {
        return this.error;
    }


    /**
     * @return whether the packet has been signed.
     */
    public boolean isSigned () {
        return ( getFlags() & SMB2_FLAGS_SIGNED ) != 0;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#getExpiration()
     */
    @Override
    public Long getExpiration () {
        return this.expiration;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#setExpiration(java.lang.Long)
     */
    @Override
    public void setExpiration ( Long exp ) {
        this.expiration = exp;
    }


    /**
     * @return whether the interim response has been handled
     */
    public boolean isAsyncHandled () {
        return this.asyncHandled;
    }


    /**
     * @param asyncHandled
     *            the asyncHandled to set
     */
    public void setAsyncHandled ( boolean asyncHandled ) {
        this.asyncHandled = asyncHandled;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#getException()
     */
    @Override
    public Exception getException () {
        return this.exception;
    }


    /**
     * 
     * @return error status code
     */
    @Override
    public final int getErrorCode () {
        return getStatus();
    }


    /**
     * 
     * @return whether signature verification failed
     */
    @Override
    public final boolean isVerifyFailed () {
        return this.verifyFailed;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#getGrantedCredits()
     */
    @Override
    public int getGrantedCredits () {
        return getCredit();
    }


    /**
     * {@inheritDoc}
     * 
     * @throws SMBProtocolDecodingException
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#haveResponse(byte[], int, int)
     */
    @Override
    protected void haveResponse ( byte[] buffer, int start, int len ) throws SMBProtocolDecodingException {
        if ( isRetainPayload() ) {
            byte[] payload = new byte[len];
            System.arraycopy(buffer, start, payload, 0, len);
            setRawPayload(payload);
        }

        if ( !verifySignature(buffer, start, len) ) {
            throw new SMBProtocolDecodingException("Signature verification failed for " + getClass().getName());
        }

        setAsyncHandled(false);
        received();
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#verifySignature(byte[], int, int)
     */
    @Override
    public boolean verifySignature ( byte[] buffer, int i, int size ) {
        // observed too that signatures on error responses are sometimes wrong??
        // Looks like the failure case also is just reflecting back the signature we sent

        // with SMB3's negotiation validation it's no longer possible to ignore this (on the validation response)
        // make sure that validation is performed in any case
        Smb2SigningDigest dgst = getDigest();
        if ( dgst != null && !isAsync() && ( getConfig().isRequireSecureNegotiate() || getErrorCode() == NtStatus.NT_STATUS_OK ) ) {
            // TODO: SMB2 - do we need to check the MIDs?
            // We only read what we were waiting for, so first guess would be no.
            boolean verify = dgst.verify(buffer, i, size, 0, this);
            this.verifyFailed = verify;
            return !verify;
        }
        return true;
    }

}
