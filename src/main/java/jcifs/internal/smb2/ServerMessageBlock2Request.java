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


import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.Request;


/**
 * @author mbechler
 * @param <T>
 *            request type
 *
 */
public abstract class ServerMessageBlock2Request <T extends ServerMessageBlock2Response> extends ServerMessageBlock2
        implements CommonServerMessageBlockRequest, Request<T> {

    private T response;
    private Integer overrideTimeout;


    /**
     * @param config
     */
    protected ServerMessageBlock2Request ( Configuration config ) {
        super(config);
    }


    /**
     * @param config
     * @param command
     */
    public ServerMessageBlock2Request ( Configuration config, int command ) {
        super(config, command);
    }


    @Override
    public ServerMessageBlock2Request<T> ignoreDisconnect () {
        return this;
    }


    @Override
    public ServerMessageBlock2Request<?> getNext () {
        return (ServerMessageBlock2Request<?>) super.getNext();
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Request#isCancel()
     */
    @Override
    public boolean isCancel () {
        return false;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#isResponseAsync()
     */
    @Override
    public boolean isResponseAsync () {
        return getAsyncId() != 0;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#allowChain(jcifs.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public boolean allowChain ( CommonServerMessageBlockRequest next ) {
        return getConfig().isAllowCompound(getClass().getSimpleName()) && getConfig().isAllowCompound(next.getClass().getSimpleName());
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#createCancel()
     */
    @Override
    public CommonServerMessageBlockRequest createCancel () {
        return new Smb2CancelRequest(getConfig(), getMid(), getAsyncId());
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#split()
     */
    @Override
    public CommonServerMessageBlockRequest split () {
        ServerMessageBlock2Request<?> n = getNext();
        if ( n != null ) {
            setNext(null);
            n.clearFlags(SMB2_FLAGS_RELATED_OPERATIONS);
        }
        return n;
    }


    /**
     * 
     * @param next
     */
    public void setNext ( ServerMessageBlock2Request<?> next ) {
        super.setNext(next);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Request#getCreditCost()
     */
    @Override
    public int getCreditCost () {
        return 1;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Request#setRequestCredits(int)
     */
    @Override
    public void setRequestCredits ( int credits ) {
        setCredit(credits);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#getOverrideTimeout()
     */
    @Override
    public final Integer getOverrideTimeout () {
        return this.overrideTimeout;
    }


    /**
     * @param overrideTimeout
     *            the overrideTimeout to set
     */
    public final void setOverrideTimeout ( Integer overrideTimeout ) {
        this.overrideTimeout = overrideTimeout;
    }


    /**
     * 
     * @return create response
     */
    @Override
    public T initResponse ( CIFSContext tc ) {
        T resp = createResponse(tc, this);
        if ( resp == null ) {
            return null;
        }
        resp.setDigest(getDigest());
        setResponse(resp);

        ServerMessageBlock2 n = getNext();
        if ( n instanceof ServerMessageBlock2Request<?> ) {
            resp.setNext( ( (ServerMessageBlock2Request<?>) n ).initResponse(tc));
        }
        return resp;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#setTid(int)
     */
    @Override
    public void setTid ( int t ) {
        setTreeId(t);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#encode(byte[], int)
     */
    @Override
    public int encode ( byte[] dst, int dstIndex ) {
        int len = super.encode(dst, dstIndex);
        int exp = size();
        int actual = getLength();
        if ( exp != actual ) {
            throw new IllegalStateException(String.format("Wrong size calculation have %d expect %d", exp, actual));
        }
        return len;
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#getResponse()
     */
    @Override
    public T getResponse () {
        return this.response;
    }


    /**
     * @param config2
     * @return
     */
    protected abstract T createResponse ( CIFSContext tc, ServerMessageBlock2Request<T> req );


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#setResponse(jcifs.internal.CommonServerMessageBlockResponse)
     */
    @SuppressWarnings ( "unchecked" )
    @Override
    public final void setResponse ( CommonServerMessageBlockResponse msg ) {
        if ( msg != null && ! ( msg instanceof ServerMessageBlock2 ) ) {
            throw new IllegalArgumentException("Incompatible response");
        }
        this.response = (T) msg;
    }
}
