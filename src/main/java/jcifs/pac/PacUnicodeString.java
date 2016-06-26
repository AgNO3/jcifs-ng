/*
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
package jcifs.pac;


@SuppressWarnings ( "javadoc" )
public class PacUnicodeString {

    private short length;
    private short maxLength;
    private int pointer;


    public PacUnicodeString ( short length, short maxLength, int pointer ) {
        super();
        this.length = length;
        this.maxLength = maxLength;
        this.pointer = pointer;
    }


    public short getLength () {
        return this.length;
    }


    public short getMaxLength () {
        return this.maxLength;
    }


    public int getPointer () {
        return this.pointer;
    }


    public String check ( String string ) throws PACDecodingException {
        if ( this.pointer == 0 && string != null )
            throw new PACDecodingException("Non-empty string");

        int expected = this.length / 2;
        if ( string.length() != expected ) {
            throw new PACDecodingException("Invalid string length, expected " + expected + ", have " + string.length());
        }

        return string;
    }
}
