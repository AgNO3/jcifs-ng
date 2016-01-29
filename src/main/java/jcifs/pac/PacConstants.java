package jcifs.pac;


public interface PacConstants {

    static final int PAC_VERSION = 0;

    static final int LOGON_INFO = 1;
    static final int CREDENTIAL_TYPE = 2;
    static final int SERVER_CHECKSUM = 6;
    static final int PRIVSVR_CHECKSUM = 7;

    static final int LOGON_EXTRA_SIDS = 0x20;
    static final int LOGON_RESOURCE_GROUPS = 0x200;

    static final int MD5_KRB_SALT = 17;
    static final int MD5_BLOCK_LENGTH = 64;

}
