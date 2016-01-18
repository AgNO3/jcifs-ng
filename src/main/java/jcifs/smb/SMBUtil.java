/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 18.01.2016 by mbechler
 */
package jcifs.smb;


import jcifs.SmbConstants;


/**
 * @author mbechler
 *
 */
public class SMBUtil {

    static void writeInt2 ( long val, byte[] dst, int dstIndex ) {
        dst[ dstIndex ] = (byte) ( val );
        dst[ ++dstIndex ] = (byte) ( val >> 8 );
    }


    static void writeInt4 ( long val, byte[] dst, int dstIndex ) {
        dst[ dstIndex ] = (byte) ( val );
        dst[ ++dstIndex ] = (byte) ( val >>= 8 );
        dst[ ++dstIndex ] = (byte) ( val >>= 8 );
        dst[ ++dstIndex ] = (byte) ( val >> 8 );
    }


    static int readInt2 ( byte[] src, int srcIndex ) {
        return ( src[ srcIndex ] & 0xFF ) + ( ( src[ srcIndex + 1 ] & 0xFF ) << 8 );
    }


    static int readInt4 ( byte[] src, int srcIndex ) {
        return ( src[ srcIndex ] & 0xFF ) + ( ( src[ srcIndex + 1 ] & 0xFF ) << 8 ) + ( ( src[ srcIndex + 2 ] & 0xFF ) << 16 )
                + ( ( src[ srcIndex + 3 ] & 0xFF ) << 24 );
    }


    static long readInt8 ( byte[] src, int srcIndex ) {
        return ( readInt4(src, srcIndex) & 0xFFFFFFFFL ) + ( (long) ( readInt4(src, srcIndex + 4) ) << 32 );
    }


    static void writeInt8 ( long val, byte[] dst, int dstIndex ) {
        dst[ dstIndex ] = (byte) ( val );
        dst[ ++dstIndex ] = (byte) ( val >>= 8 );
        dst[ ++dstIndex ] = (byte) ( val >>= 8 );
        dst[ ++dstIndex ] = (byte) ( val >>= 8 );
        dst[ ++dstIndex ] = (byte) ( val >>= 8 );
        dst[ ++dstIndex ] = (byte) ( val >>= 8 );
        dst[ ++dstIndex ] = (byte) ( val >>= 8 );
        dst[ ++dstIndex ] = (byte) ( val >> 8 );
    }


    static long readTime ( byte[] src, int srcIndex ) {
        int low = readInt4(src, srcIndex);
        int hi = readInt4(src, srcIndex + 4);
        long t = ( (long) hi << 32L ) | ( low & 0xFFFFFFFFL );
        t = ( t / 10000L - SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601 );
        return t;
    }


    static void writeTime ( long t, byte[] dst, int dstIndex ) {
        if ( t != 0L ) {
            t = ( t + SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601 ) * 10000L;
        }
        writeInt8(t, dst, dstIndex);
    }


    static long readUTime ( byte[] buffer, int bufferIndex ) {
        return readInt4(buffer, bufferIndex) * 1000L;
    }

    static final byte[] SMB_HEADER = {
        (byte) 0xFF, (byte) 'S', (byte) 'M', (byte) 'B', (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00
    };

    static final byte[] SMB2_HEADER_SYNC = {
        (byte) 0xFE, (byte) 'S', (byte) 'M', (byte) 'B', // ProtocolId
        (byte) 64, (byte) 0x00, // StructureSize (LE)
        (byte) 0x00, (byte) 0x00, // CreditCharge (reserved 2.0.2)
        (byte) 0x00, (byte) 0x00, // ChannelSequence
        (byte) 0x00, (byte) 0x00, // Reserved
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Status
        (byte) 0x00, (byte) 0x00, // Command
        (byte) 0x00, (byte) 0x00, // CreditRequest/CreditResponse
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Flags
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // NextCommand
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // MessageId
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Reserved / AsyncId
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // TreeId / AsyncId
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // SessionId
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Signature
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Signature
                                                                                                                // (cont)
    };

}
