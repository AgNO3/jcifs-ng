/*
 * © 2017 AgNO3 Gmbh & Co. KG
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs.ntlmssp.av;


import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import jcifs.CIFSException;
import jcifs.internal.util.SMBUtil;


/**
 * @author mbechler
 *
 */
public final class AvPairs {

    private AvPairs () {}


    /**
     * Decode a list of AvPairs
     * 
     * @param data
     * @return individual pairs
     * @throws CIFSException
     */
    public static List<AvPair> decode ( byte[] data ) throws CIFSException {
        List<AvPair> pairs = new LinkedList<>();
        int pos = 0;
        boolean foundEnd = false;
        while ( pos + 4 <= data.length ) {
            int avId = SMBUtil.readInt2(data, pos);
            int avLen = SMBUtil.readInt2(data, pos + 2);
            pos += 4;

            if ( avId == AvPair.MsvAvEOL ) {
                if ( avLen != 0 ) {
                    throw new CIFSException("Invalid avLen for AvEOL");
                }
                foundEnd = true;
                break;
            }

            byte[] raw = new byte[avLen];
            System.arraycopy(data, pos, raw, 0, avLen);
            pairs.add(parseAvPair(avId, raw));

            pos += avLen;
        }
        if ( !foundEnd ) {
            throw new CIFSException("Missing AvEOL");
        }
        return pairs;
    }


    /**
     * 
     * @param pairs
     * @param type
     * @return whether the list contains a pair of that type
     */
    public static boolean contains ( List<AvPair> pairs, int type ) {
        if ( pairs == null ) {
            return false;
        }
        for ( AvPair p : pairs ) {
            if ( p.getType() == type ) {
                return true;
            }
        }
        return false;
    }


    /**
     * 
     * @param pairs
     * @param type
     * @return first occurance of the given type
     */
    public static AvPair get ( List<AvPair> pairs, int type ) {
        Iterator<AvPair> it = pairs.iterator();
        while ( it.hasNext() ) {
            AvPair p = it.next();
            if ( p.getType() == type ) {
                return p;
            }
        }
        return null;
    }


    /**
     * Remove all occurances of the given type
     * 
     * @param pairs
     * @param type
     */
    public static void remove ( List<AvPair> pairs, int type ) {
        Iterator<AvPair> it = pairs.iterator();
        while ( it.hasNext() ) {
            AvPair p = it.next();
            if ( p.getType() == type ) {
                it.remove();
            }
        }
    }


    /**
     * Replace all occurances of the given type
     * 
     * @param pairs
     * @param rep
     */
    public static void replace ( List<AvPair> pairs, AvPair rep ) {
        remove(pairs, rep.getType());
        pairs.add(rep);
    }


    /**
     * 
     * @param pairs
     * @return encoded avpairs
     */
    public static byte[] encode ( List<AvPair> pairs ) {
        int size = 0;
        for ( AvPair p : pairs ) {
            size += 4 + p.getRaw().length;
        }
        size += 4;

        byte[] enc = new byte[size];
        int pos = 0;
        for ( AvPair p : pairs ) {
            byte[] raw = p.getRaw();
            SMBUtil.writeInt2(p.getType(), enc, pos);
            SMBUtil.writeInt2(raw.length, enc, pos + 2);
            System.arraycopy(raw, 0, enc, pos + 4, raw.length);
            pos += 4 + raw.length;
        }

        // MsvAvEOL
        SMBUtil.writeInt2(AvPair.MsvAvEOL, enc, pos);
        SMBUtil.writeInt2(0, enc, pos + 2);
        pos += 4;
        return enc;
    }


    private static AvPair parseAvPair ( int avId, byte[] raw ) {
        switch ( avId ) {
        case AvPair.MsvAvFlags:
            return new AvFlags(raw);
        case AvPair.MsvAvTimestamp:
            return new AvTimestamp(raw);
        case AvPair.MsvAvTargetName:
            return new AvTargetName(raw);
        case AvPair.MsvAvSingleHost:
            return new AvSingleHost(raw);
        case AvPair.MsvAvChannelBindings:
            return new AvChannelBindings(raw);
        default:
            return new AvPair(avId, raw);
        }
    }
}
