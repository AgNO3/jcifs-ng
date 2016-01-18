/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 18.01.2016 by mbechler
 */
package jcifs.tests;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;


/**
 * @author mbechler
 *
 */
@RunWith ( Suite.class )
@SuiteClasses ( {
    ContextTests.class, KerberosTests.class
} )
public class AllTests {

}
