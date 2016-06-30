/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs.tests;


import org.junit.runner.Description;
import org.junit.runner.notification.RunListener;
import org.junit.runner.notification.RunListener.ThreadSafe;;


/**
 * @author mbechler
 *
 */
@ThreadSafe
public class PrintingRunListener extends RunListener {

    @Override
    public void testStarted ( Description description ) throws Exception {
        super.testRunStarted(description);

    }


    @Override
    public void testFinished ( Description description ) throws Exception {
        super.testFinished(description);
        System.err.println("Ran " + description.getDisplayName());
    }


    @Override
    public void testIgnored ( Description description ) throws Exception {
        super.testIgnored(description);
        System.err.println("Skipped " + description.getDisplayName());
    }

}
