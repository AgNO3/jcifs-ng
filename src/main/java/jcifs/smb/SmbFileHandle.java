/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 14.03.2017 by mbechler
 */
package jcifs.smb;


/**
 * @author mbechler
 *
 */
public interface SmbFileHandle extends AutoCloseable {

    /**
     * @return the tree
     */
    SmbTreeHandle getTree ();


    /**
     * @return whether the file descriptor is valid
     */
    boolean isValid ();


    /**
     * @param lastWriteTime
     * @throws SmbException
     */
    void close ( long lastWriteTime ) throws SmbException;


    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    void close () throws SmbException;


    /**
     * @throws SmbException
     * 
     */
    void release () throws SmbException;

}