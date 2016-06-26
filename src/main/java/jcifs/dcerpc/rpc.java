package jcifs.dcerpc;


import javax.annotation.Generated;

import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;
import jcifs.dcerpc.ndr.NdrObject;


@Generated ( "midlc" )
@SuppressWarnings ( "all" )
public class rpc {

    public static class uuid_t extends NdrObject {

        public int time_low;
        public short time_mid;
        public short time_hi_and_version;
        public byte clock_seq_hi_and_reserved;
        public byte clock_seq_low;
        public byte[] node;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.time_low);
            _dst.enc_ndr_short(this.time_mid);
            _dst.enc_ndr_short(this.time_hi_and_version);
            _dst.enc_ndr_small(this.clock_seq_hi_and_reserved);
            _dst.enc_ndr_small(this.clock_seq_low);
            int _nodes = 6;
            int _nodei = _dst.index;
            _dst.advance(1 * _nodes);

            _dst = _dst.derive(_nodei);
            for ( int _i = 0; _i < _nodes; _i++ ) {
                _dst.enc_ndr_small(this.node[ _i ]);
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.time_low = _src.dec_ndr_long();
            this.time_mid = (short) _src.dec_ndr_short();
            this.time_hi_and_version = (short) _src.dec_ndr_short();
            this.clock_seq_hi_and_reserved = (byte) _src.dec_ndr_small();
            this.clock_seq_low = (byte) _src.dec_ndr_small();
            int _nodes = 6;
            int _nodei = _src.index;
            _src.advance(1 * _nodes);

            if ( this.node == null ) {
                if ( _nodes < 0 || _nodes > 0xFFFF )
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                this.node = new byte[_nodes];
            }
            _src = _src.derive(_nodei);
            for ( int _i = 0; _i < _nodes; _i++ ) {
                this.node[ _i ] = (byte) _src.dec_ndr_small();
            }
        }
    }

    public static class policy_handle extends NdrObject {

        public int type;
        public uuid_t uuid;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.type);
            if ( this.uuid == null )
                throw new NdrException(NdrException.NO_NULL_REF);
            _dst.enc_ndr_long(this.uuid.time_low);
            _dst.enc_ndr_short(this.uuid.time_mid);
            _dst.enc_ndr_short(this.uuid.time_hi_and_version);
            _dst.enc_ndr_small(this.uuid.clock_seq_hi_and_reserved);
            _dst.enc_ndr_small(this.uuid.clock_seq_low);
            int _uuid_nodes = 6;
            int _uuid_nodei = _dst.index;
            _dst.advance(1 * _uuid_nodes);

            _dst = _dst.derive(_uuid_nodei);
            for ( int _i = 0; _i < _uuid_nodes; _i++ ) {
                _dst.enc_ndr_small(this.uuid.node[ _i ]);
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.type = _src.dec_ndr_long();
            _src.align(4);
            if ( this.uuid == null ) {
                this.uuid = new uuid_t();
            }
            this.uuid.time_low = _src.dec_ndr_long();
            this.uuid.time_mid = (short) _src.dec_ndr_short();
            this.uuid.time_hi_and_version = (short) _src.dec_ndr_short();
            this.uuid.clock_seq_hi_and_reserved = (byte) _src.dec_ndr_small();
            this.uuid.clock_seq_low = (byte) _src.dec_ndr_small();
            int _uuid_nodes = 6;
            int _uuid_nodei = _src.index;
            _src.advance(1 * _uuid_nodes);

            if ( this.uuid.node == null ) {
                if ( _uuid_nodes < 0 || _uuid_nodes > 0xFFFF )
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                this.uuid.node = new byte[_uuid_nodes];
            }
            _src = _src.derive(_uuid_nodei);
            for ( int _i = 0; _i < _uuid_nodes; _i++ ) {
                this.uuid.node[ _i ] = (byte) _src.dec_ndr_small();
            }
        }
    }

    public static class unicode_string extends NdrObject {

        public short length;
        public short maximum_length;
        public short[] buffer;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_short(this.length);
            _dst.enc_ndr_short(this.maximum_length);
            _dst.enc_ndr_referent(this.buffer, 1);

            if ( this.buffer != null ) {
                _dst = _dst.deferred;
                int _bufferl = this.length / 2;
                int _buffers = this.maximum_length / 2;
                _dst.enc_ndr_long(_buffers);
                _dst.enc_ndr_long(0);
                _dst.enc_ndr_long(_bufferl);
                int _bufferi = _dst.index;
                _dst.advance(2 * _bufferl);

                _dst = _dst.derive(_bufferi);
                for ( int _i = 0; _i < _bufferl; _i++ ) {
                    _dst.enc_ndr_short(this.buffer[ _i ]);
                }
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.length = (short) _src.dec_ndr_short();
            this.maximum_length = (short) _src.dec_ndr_short();
            int _bufferp = _src.dec_ndr_long();

            if ( _bufferp != 0 ) {
                _src = _src.deferred;
                int _buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                int _bufferl = _src.dec_ndr_long();
                int _bufferi = _src.index;
                _src.advance(2 * _bufferl);

                if ( this.buffer == null ) {
                    if ( _buffers < 0 || _buffers > 0xFFFF )
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    this.buffer = new short[_buffers];
                }
                _src = _src.derive(_bufferi);
                for ( int _i = 0; _i < _bufferl; _i++ ) {
                    this.buffer[ _i ] = (short) _src.dec_ndr_short();
                }
            }
        }
    }

    public static class sid_t extends NdrObject {

        public byte revision;
        public byte sub_authority_count;
        public byte[] identifier_authority;
        public int[] sub_authority;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            int _sub_authoritys = this.sub_authority_count;
            _dst.enc_ndr_long(_sub_authoritys);
            _dst.enc_ndr_small(this.revision);
            _dst.enc_ndr_small(this.sub_authority_count);
            int _identifier_authoritys = 6;
            int _identifier_authorityi = _dst.index;
            _dst.advance(1 * _identifier_authoritys);
            int _sub_authorityi = _dst.index;
            _dst.advance(4 * _sub_authoritys);

            _dst = _dst.derive(_identifier_authorityi);
            for ( int _i = 0; _i < _identifier_authoritys; _i++ ) {
                _dst.enc_ndr_small(this.identifier_authority[ _i ]);
            }
            _dst = _dst.derive(_sub_authorityi);
            for ( int _i = 0; _i < _sub_authoritys; _i++ ) {
                _dst.enc_ndr_long(this.sub_authority[ _i ]);
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            int _sub_authoritys = _src.dec_ndr_long();
            this.revision = (byte) _src.dec_ndr_small();
            this.sub_authority_count = (byte) _src.dec_ndr_small();
            int _identifier_authoritys = 6;
            int _identifier_authorityi = _src.index;
            _src.advance(1 * _identifier_authoritys);
            int _sub_authorityi = _src.index;
            _src.advance(4 * _sub_authoritys);

            if ( this.identifier_authority == null ) {
                if ( _identifier_authoritys < 0 || _identifier_authoritys > 0xFFFF )
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                this.identifier_authority = new byte[_identifier_authoritys];
            }
            _src = _src.derive(_identifier_authorityi);
            for ( int _i = 0; _i < _identifier_authoritys; _i++ ) {
                this.identifier_authority[ _i ] = (byte) _src.dec_ndr_small();
            }
            if ( this.sub_authority == null ) {
                if ( _sub_authoritys < 0 || _sub_authoritys > 0xFFFF )
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                this.sub_authority = new int[_sub_authoritys];
            }
            _src = _src.derive(_sub_authorityi);
            for ( int _i = 0; _i < _sub_authoritys; _i++ ) {
                this.sub_authority[ _i ] = _src.dec_ndr_long();
            }
        }
    }
}
