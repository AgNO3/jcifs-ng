package jcifs.internal.fscc;

import jcifs.Decodable;
import jcifs.Encodable;
import jcifs.SymlinkBehavior;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Strings;

import java.nio.charset.StandardCharsets;

public class SymlinkReparseData implements Encodable, Decodable, SymlinkInfo {

    public static final int SYMLINK_FLAG_RELATIVE = 0x1;

    private final int ReparseTag = 0xA000000C;

    private String substituteName;
    private String printName;

    private int flags;


    public SymlinkReparseData(String substituteName, String printName, boolean relative) {
        this.substituteName = substituteName;
        this.printName = printName;
        this.flags = relative ? SYMLINK_FLAG_RELATIVE : 0;
    }

    public SymlinkReparseData()  {

    }

    @Override
    public String getPrintName() {
        return printName;
    }

    @Override
    public String getSubstituteName() {
        return substituteName;
    }

    @Override
    public boolean isRelative() {
        return (this.flags & SYMLINK_FLAG_RELATIVE) != 0;
    }

    @Override
    public int encode(byte[] dst, int dstIndex) {
        int start = dstIndex;
        SMBUtil.writeInt4(ReparseTag, dst, dstIndex);
        dstIndex += 4;

        SMBUtil.writeInt2(12 + 2*this.substituteName.length() + 2*this.printName.length(), dst, dstIndex);
        // 2 Reserved
        dstIndex += 4;

        int subNameOffset = dstIndex;
        SMBUtil.writeInt2(this.substituteName.length()*2, dst,dstIndex + 2);
        dstIndex += 4;

        int printNameOffset = dstIndex;
        SMBUtil.writeInt2(this.printName.length()*2, dst,dstIndex + 2);
        dstIndex += 4;


        SMBUtil.writeInt4(this.flags, dst, dstIndex);
        dstIndex += 4;


        int pathBufStart = dstIndex;

        byte[] subNameBytes = this.substituteName.getBytes(StandardCharsets.UTF_16LE);
        SMBUtil.writeInt2(dstIndex - pathBufStart, dst, subNameOffset);
        System.arraycopy(subNameBytes, 0, dst, dstIndex, subNameBytes.length);
        dstIndex += subNameBytes.length;

        byte[] printNameBytes = this.printName.getBytes(StandardCharsets.UTF_16LE);
        SMBUtil.writeInt2(dstIndex - pathBufStart, dst, printNameOffset);
        System.arraycopy(printNameBytes, 0, dst, dstIndex, printNameBytes.length);
        dstIndex += printNameBytes.length;

        return dstIndex - start;
    }

    @Override
    public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        // Read total allocation units.
        int tag = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        if ( tag != ReparseTag ) {
            throw new SMBProtocolDecodingException("Unsupported reparse data type");
        }


        int reparseDataLength = SMBUtil.readInt2(buffer, bufferIndex);
        //  2 byte Reserved
        bufferIndex += 4;

        if ( (reparseDataLength+8) > len)  {
            throw new SMBProtocolDecodingException("reparseDataLength too large");
        }

        int subNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
        int subNameLength = SMBUtil.readInt2(buffer, bufferIndex+2);
        bufferIndex += 4;

        int printNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
        int printNameLength = SMBUtil.readInt2(buffer, bufferIndex+2);
        bufferIndex += 4;

        flags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.substituteName = Strings.fromUNIBytes(buffer, bufferIndex+subNameOffset,  subNameLength);
        this.printName = Strings.fromUNIBytes(buffer, bufferIndex+printNameOffset,  printNameLength);

        bufferIndex += reparseDataLength - 12;

        return bufferIndex - start;
    }

    @Override
    public int size() {
        return 20 + 2*this.substituteName.length() + 2*this.printName.length();
    }
}
