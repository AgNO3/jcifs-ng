package jcifs.internal.fscc;

import jcifs.Encodable;
import jcifs.internal.util.SMBUtil;

import java.nio.charset.StandardCharsets;

public class FsctlDeleteReparsePointRequest implements Encodable  {

    private final int ReparseTag = 0xA000000C;


    public FsctlDeleteReparsePointRequest() {
    }


    @Override
    public int encode(byte[] dst, int dstIndex) {
        int start = dstIndex;
        SMBUtil.writeInt4(ReparseTag, dst, dstIndex);
        dstIndex += 4;

        SMBUtil.writeInt2(0, dst, dstIndex);
        // 2 Reserved
        dstIndex += 4;


        return dstIndex - start;
    }

    @Override
    public int size() {
        return 8;
    }
}
