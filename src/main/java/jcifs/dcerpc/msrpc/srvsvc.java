package jcifs.dcerpc.msrpc;


import javax.annotation.Generated;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;
import jcifs.dcerpc.ndr.NdrObject;


@Generated ( "midlc" )
@SuppressWarnings ( "all" )
public class srvsvc {

    public static String getSyntax () {
        return "4b324fc8-1670-01d3-1278-5a47bf6ee188:3.0";
    }

    public static class ShareInfo0 extends NdrObject {

        public String netname;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(this.netname, 1);

            if ( this.netname != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.netname);

            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            int _netnamep = _src.dec_ndr_long();

            if ( _netnamep != 0 ) {
                _src = _src.deferred;
                this.netname = _src.dec_ndr_string();

            }
        }
    }

    public static class ShareInfoCtr0 extends NdrObject {

        public int count;
        public ShareInfo0[] array;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.count);
            _dst.enc_ndr_referent(this.array, 1);

            if ( this.array != null ) {
                _dst = _dst.deferred;
                int _arrays = this.count;
                _dst.enc_ndr_long(_arrays);
                int _arrayi = _dst.index;
                _dst.advance(4 * _arrays);

                _dst = _dst.derive(_arrayi);
                for ( int _i = 0; _i < _arrays; _i++ ) {
                    this.array[ _i ].encode(_dst);
                }
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.count = _src.dec_ndr_long();
            int _arrayp = _src.dec_ndr_long();

            if ( _arrayp != 0 ) {
                _src = _src.deferred;
                int _arrays = _src.dec_ndr_long();
                int _arrayi = _src.index;
                _src.advance(4 * _arrays);

                if ( this.array == null ) {
                    if ( _arrays < 0 || _arrays > 0xFFFF )
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    this.array = new ShareInfo0[_arrays];
                }
                _src = _src.derive(_arrayi);
                for ( int _i = 0; _i < _arrays; _i++ ) {
                    if ( this.array[ _i ] == null ) {
                        this.array[ _i ] = new ShareInfo0();
                    }
                    this.array[ _i ].decode(_src);
                }
            }
        }
    }

    public static class ShareInfo1 extends NdrObject {

        public String netname;
        public int type;
        public String remark;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(this.netname, 1);
            _dst.enc_ndr_long(this.type);
            _dst.enc_ndr_referent(this.remark, 1);

            if ( this.netname != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.netname);

            }
            if ( this.remark != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.remark);

            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            int _netnamep = _src.dec_ndr_long();
            this.type = _src.dec_ndr_long();
            int _remarkp = _src.dec_ndr_long();

            if ( _netnamep != 0 ) {
                _src = _src.deferred;
                this.netname = _src.dec_ndr_string();

            }
            if ( _remarkp != 0 ) {
                _src = _src.deferred;
                this.remark = _src.dec_ndr_string();

            }
        }
    }

    public static class ShareInfoCtr1 extends NdrObject {

        public int count;
        public ShareInfo1[] array;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.count);
            _dst.enc_ndr_referent(this.array, 1);

            if ( this.array != null ) {
                _dst = _dst.deferred;
                int _arrays = this.count;
                _dst.enc_ndr_long(_arrays);
                int _arrayi = _dst.index;
                _dst.advance(12 * _arrays);

                _dst = _dst.derive(_arrayi);
                for ( int _i = 0; _i < _arrays; _i++ ) {
                    this.array[ _i ].encode(_dst);
                }
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.count = _src.dec_ndr_long();
            int _arrayp = _src.dec_ndr_long();

            if ( _arrayp != 0 ) {
                _src = _src.deferred;
                int _arrays = _src.dec_ndr_long();
                int _arrayi = _src.index;
                _src.advance(12 * _arrays);

                if ( this.array == null ) {
                    if ( _arrays < 0 || _arrays > 0xFFFF )
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    this.array = new ShareInfo1[_arrays];
                }
                _src = _src.derive(_arrayi);
                for ( int _i = 0; _i < _arrays; _i++ ) {
                    if ( this.array[ _i ] == null ) {
                        this.array[ _i ] = new ShareInfo1();
                    }
                    this.array[ _i ].decode(_src);
                }
            }
        }
    }

    public static class ShareInfo502 extends NdrObject {

        public String netname;
        public int type;
        public String remark;
        public int permissions;
        public int max_uses;
        public int current_uses;
        public String path;
        public String password;
        public int sd_size;
        public byte[] security_descriptor;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(this.netname, 1);
            _dst.enc_ndr_long(this.type);
            _dst.enc_ndr_referent(this.remark, 1);
            _dst.enc_ndr_long(this.permissions);
            _dst.enc_ndr_long(this.max_uses);
            _dst.enc_ndr_long(this.current_uses);
            _dst.enc_ndr_referent(this.path, 1);
            _dst.enc_ndr_referent(this.password, 1);
            _dst.enc_ndr_long(this.sd_size);
            _dst.enc_ndr_referent(this.security_descriptor, 1);

            if ( this.netname != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.netname);

            }
            if ( this.remark != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.remark);

            }
            if ( this.path != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.path);

            }
            if ( this.password != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.password);

            }
            if ( this.security_descriptor != null ) {
                _dst = _dst.deferred;
                int _security_descriptors = this.sd_size;
                _dst.enc_ndr_long(_security_descriptors);
                int _security_descriptori = _dst.index;
                _dst.advance(1 * _security_descriptors);

                _dst = _dst.derive(_security_descriptori);
                for ( int _i = 0; _i < _security_descriptors; _i++ ) {
                    _dst.enc_ndr_small(this.security_descriptor[ _i ]);
                }
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            int _netnamep = _src.dec_ndr_long();
            this.type = _src.dec_ndr_long();
            int _remarkp = _src.dec_ndr_long();
            this.permissions = _src.dec_ndr_long();
            this.max_uses = _src.dec_ndr_long();
            this.current_uses = _src.dec_ndr_long();
            int _pathp = _src.dec_ndr_long();
            int _passwordp = _src.dec_ndr_long();
            this.sd_size = _src.dec_ndr_long();
            int _security_descriptorp = _src.dec_ndr_long();

            if ( _netnamep != 0 ) {
                _src = _src.deferred;
                this.netname = _src.dec_ndr_string();

            }
            if ( _remarkp != 0 ) {
                _src = _src.deferred;
                this.remark = _src.dec_ndr_string();

            }
            if ( _pathp != 0 ) {
                _src = _src.deferred;
                this.path = _src.dec_ndr_string();

            }
            if ( _passwordp != 0 ) {
                _src = _src.deferred;
                this.password = _src.dec_ndr_string();

            }
            if ( _security_descriptorp != 0 ) {
                _src = _src.deferred;
                int _security_descriptors = _src.dec_ndr_long();
                int _security_descriptori = _src.index;
                _src.advance(1 * _security_descriptors);

                if ( this.security_descriptor == null ) {
                    if ( _security_descriptors < 0 || _security_descriptors > 0xFFFF )
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    this.security_descriptor = new byte[_security_descriptors];
                }
                _src = _src.derive(_security_descriptori);
                for ( int _i = 0; _i < _security_descriptors; _i++ ) {
                    this.security_descriptor[ _i ] = (byte) _src.dec_ndr_small();
                }
            }
        }
    }

    public static class ShareInfoCtr502 extends NdrObject {

        public int count;
        public ShareInfo502[] array;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.count);
            _dst.enc_ndr_referent(this.array, 1);

            if ( this.array != null ) {
                _dst = _dst.deferred;
                int _arrays = this.count;
                _dst.enc_ndr_long(_arrays);
                int _arrayi = _dst.index;
                _dst.advance(40 * _arrays);

                _dst = _dst.derive(_arrayi);
                for ( int _i = 0; _i < _arrays; _i++ ) {
                    this.array[ _i ].encode(_dst);
                }
            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.count = _src.dec_ndr_long();
            int _arrayp = _src.dec_ndr_long();

            if ( _arrayp != 0 ) {
                _src = _src.deferred;
                int _arrays = _src.dec_ndr_long();
                int _arrayi = _src.index;
                _src.advance(40 * _arrays);

                if ( this.array == null ) {
                    if ( _arrays < 0 || _arrays > 0xFFFF )
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    this.array = new ShareInfo502[_arrays];
                }
                _src = _src.derive(_arrayi);
                for ( int _i = 0; _i < _arrays; _i++ ) {
                    if ( this.array[ _i ] == null ) {
                        this.array[ _i ] = new ShareInfo502();
                    }
                    this.array[ _i ].decode(_src);
                }
            }
        }
    }

    public static class ShareEnumAll extends DcerpcMessage {

        @Override
        public int getOpnum () {
            return 0x0f;
        }

        public int retval;
        public String servername;
        public int level;
        public NdrObject info;
        public int prefmaxlen;
        public int totalentries;
        public int resume_handle;


        public ShareEnumAll ( String servername, int level, NdrObject info, int prefmaxlen, int totalentries, int resume_handle ) {
            this.servername = servername;
            this.level = level;
            this.info = info;
            this.prefmaxlen = prefmaxlen;
            this.totalentries = totalentries;
            this.resume_handle = resume_handle;
        }


        @Override
        public void encode_in ( NdrBuffer _dst ) throws NdrException {
            _dst.enc_ndr_referent(this.servername, 1);
            if ( this.servername != null ) {
                _dst.enc_ndr_string(this.servername);

            }
            _dst.enc_ndr_long(this.level);
            int _descr = this.level;
            _dst.enc_ndr_long(_descr);
            _dst.enc_ndr_referent(this.info, 1);
            if ( this.info != null ) {
                _dst = _dst.deferred;
                this.info.encode(_dst);

            }
            _dst.enc_ndr_long(this.prefmaxlen);
            _dst.enc_ndr_long(this.resume_handle);
        }


        @Override
        public void decode_out ( NdrBuffer _src ) throws NdrException {
            this.level = _src.dec_ndr_long();
            _src.dec_ndr_long(); /* union discriminant */
            int _infop = _src.dec_ndr_long();
            if ( _infop != 0 ) {
                if ( this.info == null ) { /* YOYOYO */
                    this.info = new ShareInfoCtr0();
                }
                _src = _src.deferred;
                this.info.decode(_src);

            }
            this.totalentries = _src.dec_ndr_long();
            this.resume_handle = _src.dec_ndr_long();
            this.retval = _src.dec_ndr_long();
        }
    }

    public static class ShareGetInfo extends DcerpcMessage {

        @Override
        public int getOpnum () {
            return 0x10;
        }

        public int retval;
        public String servername;
        public String sharename;
        public int level;
        public NdrObject info;


        public ShareGetInfo ( String servername, String sharename, int level, NdrObject info ) {
            this.servername = servername;
            this.sharename = sharename;
            this.level = level;
            this.info = info;
        }


        @Override
        public void encode_in ( NdrBuffer _dst ) throws NdrException {
            _dst.enc_ndr_referent(this.servername, 1);
            if ( this.servername != null ) {
                _dst.enc_ndr_string(this.servername);

            }
            _dst.enc_ndr_string(this.sharename);
            _dst.enc_ndr_long(this.level);
        }


        @Override
        public void decode_out ( NdrBuffer _src ) throws NdrException {
            _src.dec_ndr_long(); /* union discriminant */
            int _infop = _src.dec_ndr_long();
            if ( _infop != 0 ) {
                if ( this.info == null ) { /* YOYOYO */
                    this.info = new ShareInfo0();
                }
                _src = _src.deferred;
                this.info.decode(_src);

            }
            this.retval = _src.dec_ndr_long();
        }
    }

    public static class ServerInfo100 extends NdrObject {

        public int platform_id;
        public String name;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.platform_id);
            _dst.enc_ndr_referent(this.name, 1);

            if ( this.name != null ) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(this.name);

            }
        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.platform_id = _src.dec_ndr_long();
            int _namep = _src.dec_ndr_long();

            if ( _namep != 0 ) {
                _src = _src.deferred;
                this.name = _src.dec_ndr_string();

            }
        }
    }

    public static class ServerGetInfo extends DcerpcMessage {

        @Override
        public int getOpnum () {
            return 0x15;
        }

        public int retval;
        public String servername;
        public int level;
        public NdrObject info;


        public ServerGetInfo ( String servername, int level, NdrObject info ) {
            this.servername = servername;
            this.level = level;
            this.info = info;
        }


        @Override
        public void encode_in ( NdrBuffer _dst ) throws NdrException {
            _dst.enc_ndr_referent(this.servername, 1);
            if ( this.servername != null ) {
                _dst.enc_ndr_string(this.servername);

            }
            _dst.enc_ndr_long(this.level);
        }


        @Override
        public void decode_out ( NdrBuffer _src ) throws NdrException {
            _src.dec_ndr_long(); /* union discriminant */
            int _infop = _src.dec_ndr_long();
            if ( _infop != 0 ) {
                if ( this.info == null ) { /* YOYOYO */
                    this.info = new ServerInfo100();
                }
                _src = _src.deferred;
                this.info.decode(_src);

            }
            this.retval = _src.dec_ndr_long();
        }
    }

    public static class TimeOfDayInfo extends NdrObject {

        public int elapsedt;
        public int msecs;
        public int hours;
        public int mins;
        public int secs;
        public int hunds;
        public int timezone;
        public int tinterval;
        public int day;
        public int month;
        public int year;
        public int weekday;


        @Override
        public void encode ( NdrBuffer _dst ) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.elapsedt);
            _dst.enc_ndr_long(this.msecs);
            _dst.enc_ndr_long(this.hours);
            _dst.enc_ndr_long(this.mins);
            _dst.enc_ndr_long(this.secs);
            _dst.enc_ndr_long(this.hunds);
            _dst.enc_ndr_long(this.timezone);
            _dst.enc_ndr_long(this.tinterval);
            _dst.enc_ndr_long(this.day);
            _dst.enc_ndr_long(this.month);
            _dst.enc_ndr_long(this.year);
            _dst.enc_ndr_long(this.weekday);

        }


        @Override
        public void decode ( NdrBuffer _src ) throws NdrException {
            _src.align(4);
            this.elapsedt = _src.dec_ndr_long();
            this.msecs = _src.dec_ndr_long();
            this.hours = _src.dec_ndr_long();
            this.mins = _src.dec_ndr_long();
            this.secs = _src.dec_ndr_long();
            this.hunds = _src.dec_ndr_long();
            this.timezone = _src.dec_ndr_long();
            this.tinterval = _src.dec_ndr_long();
            this.day = _src.dec_ndr_long();
            this.month = _src.dec_ndr_long();
            this.year = _src.dec_ndr_long();
            this.weekday = _src.dec_ndr_long();

        }
    }

    public static class RemoteTOD extends DcerpcMessage {

        @Override
        public int getOpnum () {
            return 0x1c;
        }

        public int retval;
        public String servername;
        public TimeOfDayInfo info;


        public RemoteTOD ( String servername, TimeOfDayInfo info ) {
            this.servername = servername;
            this.info = info;
        }


        @Override
        public void encode_in ( NdrBuffer _dst ) throws NdrException {
            _dst.enc_ndr_referent(this.servername, 1);
            if ( this.servername != null ) {
                _dst.enc_ndr_string(this.servername);

            }
        }


        @Override
        public void decode_out ( NdrBuffer _src ) throws NdrException {
            int _infop = _src.dec_ndr_long();
            if ( _infop != 0 ) {
                if ( this.info == null ) { /* YOYOYO */
                    this.info = new TimeOfDayInfo();
                }
                this.info.decode(_src);

            }
            this.retval = _src.dec_ndr_long();
        }
    }
}
