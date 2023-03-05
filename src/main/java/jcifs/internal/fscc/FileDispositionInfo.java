package jcifs.internal.fscc;

import jcifs.Encodable;
import jcifs.internal.SMBProtocolDecodingException;

public class FileDispositionInfo implements Encodable, FileInformation {

    private final int DeletePending = 1;


    @Override
    public int encode(byte[] dst, int dstIndex) {
        dst[dstIndex] = DeletePending;
        return 1;
    }

    @Override
    public int size() {
        return 1;
    }

    @Override
    public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
        return 1;
    }

    @Override
    public byte getFileInformationLevel() {
        return 0xd;
    }
}
