package jcifs.pac.kerberos;


public interface KerberosConstants {

    static final String KERBEROS_OID = "1.2.840.113554.1.2.2";
    static final String KERBEROS_VERSION = "5";

    static final String KERBEROS_AP_REQ = "14";

    static final int AF_INTERNET = 2;
    static final int AF_CHANET = 5;
    static final int AF_XNS = 6;
    static final int AF_ISO = 7;

    static final int AUTH_DATA_RELEVANT = 1;
    static final int AUTH_DATA_PAC = 128;

    static final int DES_ENC_TYPE = 3;
    static final int RC4_ENC_TYPE = 23;
    static final String RC4_ALGORITHM = "ARCFOUR";
    static final String HMAC_ALGORITHM = "HmacMD5";
    static final int CONFOUNDER_SIZE = 8;
    static final int CHECKSUM_SIZE = 16;

}