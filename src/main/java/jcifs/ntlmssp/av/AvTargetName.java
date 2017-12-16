/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: Dec 16, 2017 by mbechler
 */
package jcifs.ntlmssp.av;


import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;


/**
 * @author mbechler
 *
 */
public class AvTargetName extends AvPair {

    /**
     * 
     */
    private static final Charset UTF16LE = StandardCharsets.UTF_16LE;


    /**
     * @param raw
     */
    public AvTargetName ( byte[] raw ) {
        super(AvPair.MsvAvTargetName, raw);
    }


    /**
     * 
     * @param targetName
     */
    public AvTargetName ( String targetName ) {
        this(encode(targetName));
    }


    /**
     * 
     * @return the target name
     */
    public String getTargetName () {
        return new String(getRaw(), UTF16LE);
    }


    /**
     * @param targetName
     * @return
     */
    private static byte[] encode ( String targetName ) {
        return targetName.getBytes(UTF16LE);
    }

}
