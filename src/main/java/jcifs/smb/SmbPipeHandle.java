/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 20.03.2017 by mbechler
 */
package jcifs.smb;


/**
 * @author mbechler
 *
 */
public interface SmbPipeHandle extends AutoCloseable {

    /**
     * @return the pipe
     */
    SmbNamedPipe getPipe ();


    /**
     * @return the pipe type
     */
    int getPipeType ();


    /**
     * @return the uncPath
     */
    String getUncPath ();


    /**
     * @return whether the FD is open and valid
     */
    boolean isOpen ();


    /**
     * @return whether the FD was previously open but became invalid
     */
    boolean isStale ();


    /**
     * 
     * @return this pipe's input stream
     * @throws SmbException
     */
    SmbPipeInputStream getInput () throws SmbException;


    /**
     * 
     * @return this pipe's output stream
     * @throws SmbException
     */
    SmbPipeOutputStream getOutput () throws SmbException;


    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    void close () throws SmbException;

}