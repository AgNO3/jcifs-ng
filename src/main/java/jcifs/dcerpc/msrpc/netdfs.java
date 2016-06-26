package jcifs.dcerpc.msrpc;


import javax.annotation.Generated;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;
import jcifs.dcerpc.ndr.NdrLong;
import jcifs.dcerpc.ndr.NdrObject;


@Generated ( "midlc" )
@SuppressWarnings ( "all" )
public class netdfs {

    public static String getSyntax () {
        return "4fc742e0-4a10-11cf-8273-00aa004ae673:3.0";
    }

    public static final int DFS_VOLUME_FLAVOR_STANDALONE = 0x100;
    public static final int DFS_VOLUME_FLAVOR_AD_BLOB = 0x200;
    public static final int DFS_STORAGE_STATE_OFFLINE = 0x0001;
    public static final int DFS_STORAGE_STATE_ONLINE = 0x0002;
    public static final int DFS_STORAGE_STATE_ACTIVE = 0x0004;

    public static class DfsInfo1 extends NdrObject {

        public String entry_path;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(this.entry_path, 1);

            if ( this.entry_path != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.entry_path);

            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            int _entry_pathp = _src.dec_ndr_long();

            if ( _entry_pathp != 0 ) {
                _src = _src.deferred;
                this.entry_path = _src.dec_ndr_string();

            }
        }
    }

    public static class DfsEnumArray1 extends NdrObject {

        public int count;
        public DfsInfo1[] s;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.count);
            _dst.enc_ndr_referent(this.s, 1);

            if ( this.s != null ) {
                _dst = _dst.deferred;
                int _ss = this.count;
                _dst.enc_ndr_long(_ss);
                int _si = _dst.index;
                _dst.advance(4 * _ss);

                _dst = _dst.derive(_si);
                for ( int _i = 0; _i < _ss; _i++ ) {
                    this.s[ _i ].encode(_dst);
                }
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.count = _src.dec_ndr_long();
            int _sp = _src.dec_ndr_long();

            if ( _sp != 0 ) {
                _src = _src.deferred;
                int _ss = _src.dec_ndr_long();
                int _si = _src.index;
                _src.advance(4 * _ss);

                if ( this.s == null ) {
                    if ( _ss < 0 || _ss > 0xFFFF )
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    this.s = new DfsInfo1[_ss];
                }
                _src = _src.derive(_si);
                for ( int _i = 0; _i < _ss; _i++ ) {
                    if ( this.s[ _i ] == null ) {
                        this.s[ _i ] = new DfsInfo1();
                    }
                    this.s[ _i ].decode(_src);
                }
            }
        }
    }

    public static class DfsStorageInfo extends NdrObject {

        public int state;
        public String server_name;
        public String share_name;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.state);
            _dst.enc_ndr_referent(this.server_name, 1);
            _dst.enc_ndr_referent(this.share_name, 1);

            if ( this.server_name != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.server_name);

            }
            if ( this.share_name != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.share_name);

            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.state = _src.dec_ndr_long();
            int _server_namep = _src.dec_ndr_long();
            int _share_namep = _src.dec_ndr_long();

            if ( _server_namep != 0 ) {
                _src = _src.deferred;
                this.server_name = _src.dec_ndr_string();

            }
            if ( _share_namep != 0 ) {
                _src = _src.deferred;
                this.share_name = _src.dec_ndr_string();

            }
        }
    }

    public static class DfsInfo3 extends NdrObject {

        public String path;
        public String comment;
        public int state;
        public int num_stores;
        public DfsStorageInfo[] stores;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(this.path, 1);
            _dst.enc_ndr_referent(this.comment, 1);
            _dst.enc_ndr_long(this.state);
            _dst.enc_ndr_long(this.num_stores);
            _dst.enc_ndr_referent(this.stores, 1);

            if ( this.path != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.path);

            }
            if ( this.comment != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.comment);

            }
            if ( this.stores != null ) {
                _dst = _dst.deferred;
                int _storess = this.num_stores;
                _dst.enc_ndr_long(_storess);
                int _storesi = _dst.index;
                _dst.advance(12 * _storess);

                _dst = _dst.derive(_storesi);
                for ( int _i = 0; _i < _storess; _i++ ) {
                    this.stores[ _i ].encode(_dst);
                }
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            int _pathp = _src.dec_ndr_long();
            int _commentp = _src.dec_ndr_long();
            this.state = _src.dec_ndr_long();
            this.num_stores = _src.dec_ndr_long();
            int _storesp = _src.dec_ndr_long();

            if ( _pathp != 0 ) {
                _src = _src.deferred;
                this.path = _src.dec_ndr_string();

            }
            if ( _commentp != 0 ) {
                _src = _src.deferred;
                this.comment = _src.dec_ndr_string();

            }
            if ( _storesp != 0 ) {
                _src = _src.deferred;
                int _storess = _src.dec_ndr_long();
                int _storesi = _src.index;
                _src.advance(12 * _storess);

                if ( this.stores == null ) {
                    if ( _storess < 0 || _storess > 0xFFFF )
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    this.stores = new DfsStorageInfo[_storess];
                }
                _src = _src.derive(_storesi);
                for ( int _i = 0; _i < _storess; _i++ ) {
                    if ( this.stores[ _i ] == null ) {
                        this.stores[ _i ] = new DfsStorageInfo();
                    }
                    this.stores[ _i ].decode(_src);
                }
            }
        }
    }

    public static class DfsEnumArray3 extends NdrObject {

        public int count;
        public DfsInfo3[] s;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.count);
            _dst.enc_ndr_referent(this.s, 1);

            if ( this.s != null ) {
                _dst = _dst.deferred;
                int _ss = this.count;
                _dst.enc_ndr_long(_ss);
                int _si = _dst.index;
                _dst.advance(20 * _ss);

                _dst = _dst.derive(_si);
                for ( int _i = 0; _i < _ss; _i++ ) {
                    this.s[ _i ].encode(_dst);
                }
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.count = _src.dec_ndr_long();
            int _sp = _src.dec_ndr_long();

            if ( _sp != 0 ) {
                _src = _src.deferred;
                int _ss = _src.dec_ndr_long();
                int _si = _src.index;
                _src.advance(20 * _ss);

                if ( this.s == null ) {
                    if ( _ss < 0 || _ss > 0xFFFF )
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    this.s = new DfsInfo3[_ss];
                }
                _src = _src.derive(_si);
                for ( int _i = 0; _i < _ss; _i++ ) {
                    if ( this.s[ _i ] == null ) {
                        this.s[ _i ] = new DfsInfo3();
                    }
                    this.s[ _i ].decode(_src);
                }
            }
        }
    }

    public static class DfsInfo200 extends NdrObject {

        public String dfs_name;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(this.dfs_name, 1);

            if ( this.dfs_name != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.dfs_name);

            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            int _dfs_namep = _src.dec_ndr_long();

            if ( _dfs_namep != 0 ) {
                _src = _src.deferred;
                this.dfs_name = _src.dec_ndr_string();

            }
        }
    }

    public static class DfsEnumArray200 extends NdrObject {

        public int count;
        public DfsInfo200[] s;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.count);
            _dst.enc_ndr_referent(this.s, 1);

            if ( this.s != null ) {
                _dst = _dst.deferred;
                int _ss = this.count;
                _dst.enc_ndr_long(_ss);
                int _si = _dst.index;
                _dst.advance(4 * _ss);

                _dst = _dst.derive(_si);
                for ( int _i = 0; _i < _ss; _i++ ) {
                    this.s[ _i ].encode(_dst);
                }
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.count = _src.dec_ndr_long();
            int _sp = _src.dec_ndr_long();

            if ( _sp != 0 ) {
                _src = _src.deferred;
                int _ss = _src.dec_ndr_long();
                int _si = _src.index;
                _src.advance(4 * _ss);

                if ( this.s == null ) {
                    if ( _ss < 0 || _ss > 0xFFFF )
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    this.s = new DfsInfo200[_ss];
                }
                _src = _src.derive(_si);
                for ( int _i = 0; _i < _ss; _i++ ) {
                    if ( this.s[ _i ] == null ) {
                        this.s[ _i ] = new DfsInfo200();
                    }
                    this.s[ _i ].decode(_src);
                }
            }
        }
    }

    public static class DfsInfo300 extends NdrObject {

        public int flags;
        public String dfs_name;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.flags);
            _dst.enc_ndr_referent(this.dfs_name, 1);

            if ( this.dfs_name != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.dfs_name);

            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.flags = _src.dec_ndr_long();
            int _dfs_namep = _src.dec_ndr_long();

            if ( _dfs_namep != 0 ) {
                _src = _src.deferred;
                this.dfs_name = _src.dec_ndr_string();

            }
        }
    }

    public static class DfsEnumArray300 extends NdrObject {

        public int count;
        public DfsInfo300[] s;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.count);
            _dst.enc_ndr_referent(this.s, 1);

            if ( this.s != null ) {
                _dst = _dst.deferred;
                int _ss = this.count;
                _dst.enc_ndr_long(_ss);
                int _si = _dst.index;
                _dst.advance(8 * _ss);

                _dst = _dst.derive(_si);
                for ( int _i = 0; _i < _ss; _i++ ) {
                    this.s[ _i ].encode(_dst);
                }
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.count = _src.dec_ndr_long();
            int _sp = _src.dec_ndr_long();

            if ( _sp != 0 ) {
                _src = _src.deferred;
                int _ss = _src.dec_ndr_long();
                int _si = _src.index;
                _src.advance(8 * _ss);

                if ( this.s == null ) {
                    if ( _ss < 0 || _ss > 0xFFFF )
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    this.s = new DfsInfo300[_ss];
                }
                _src = _src.derive(_si);
                for ( int _i = 0; _i < _ss; _i++ ) {
                    if ( this.s[ _i ] == null ) {
                        this.s[ _i ] = new DfsInfo300();
                    }
                    this.s[ _i ].decode(_src);
                }
            }
        }
    }

    public static class DfsEnumStruct extends NdrObject {

        public int level;
        public NdrObject e;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.level);
            int _descr = this.level;
            _dst.enc_ndr_long(_descr);
            _dst.enc_ndr_referent(this.e, 1);

            if ( this.e != null ) {
                _dst = _dst.deferred;
                this.e.encode(_dst);

            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.level = _src.dec_ndr_long();
            _src.dec_ndr_long(); /* union discriminant */
            int _ep = _src.dec_ndr_long();

            if ( _ep != 0 ) {
                if ( this.e == null ) { /* YOYOYO */
                    this.e = new DfsEnumArray1();
                }
                _src = _src.deferred;
                this.e.decode(_src);

            }
        }
    }

    public static class NetrDfsEnumEx extends DcerpcMessage {

        @Override
        public int getOpnum () {
            return 0x15;
        }

        public int retval;
        public String dfs_name;
        public int level;
        public int prefmaxlen;
        public DfsEnumStruct info;
        public NdrLong totalentries;


        public NetrDfsEnumEx ( String dfs_name, int level, int prefmaxlen, DfsEnumStruct info, NdrLong totalentries ) {
            this.dfs_name = dfs_name;
            this.level = level;
            this.prefmaxlen = prefmaxlen;
            this.info = info;
            this.totalentries = totalentries;
        }


        @Override
        public void encode_in ( NdrBuffer _dst ) throws NdrException {
            _dst.enc_ndr_string(this.dfs_name);
            _dst.enc_ndr_long(this.level);
            _dst.enc_ndr_long(this.prefmaxlen);
            _dst.enc_ndr_referent(this.info, 1);
            if ( this.info != null ) {
                this.info.encode(_dst);

            }
            _dst.enc_ndr_referent(this.totalentries, 1);
            if ( this.totalentries != null ) {
                this.totalentries.encode(_dst);

            }
        }


        @Override
        public void decode_out ( NdrBuffer _src ) throws NdrException {
            int _infop = _src.dec_ndr_long();
            if ( _infop != 0 ) {
                if ( this.info == null ) { /* YOYOYO */
                    this.info = new DfsEnumStruct();
                }
                this.info.decode(_src);

            }
            int _totalentriesp = _src.dec_ndr_long();
            if ( _totalentriesp != 0 ) {
                this.totalentries.decode(_src);

            }
            this.retval = _src.dec_ndr_long();
        }
    }
}
