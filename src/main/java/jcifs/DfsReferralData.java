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
package jcifs;


/**
 * Information returned in DFS referrals
 * 
 * @author mbechler
 * @internal
 */
public interface DfsReferralData {

    /**
     * 
     * @param type
     * @return the referral adapted to type
     * @throws ClassCastException
     *             if the type is not valid for this object
     */
    <T extends DfsReferralData> T unwrap ( Class<T> type );


    /**
     * @return the server this referral points to
     */
    String getServer ();


    /**
     * 
     * @return the domain this referral is for
     */
    String getDomain ();


    /**
     * @return the share this referral points to
     */
    String getShare ();


    /**
     * @return the number of characters from the unc path that were consumed by this referral
     */
    int getPathConsumed ();


    /**
     * @return the replacement path for this referal
     */
    String getPath ();


    /**
     * @return the expiration time of this entry
     */
    long getExpiration ();


    /**
     * 
     * @return pointer to next referral, points to self if there is no further referral
     */
    DfsReferralData next ();


    /**
     * @return the link
     */
    String getLink ();

}
