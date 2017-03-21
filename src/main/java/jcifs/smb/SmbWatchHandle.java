/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 20.03.2017 by mbechler
 */
package jcifs.smb;


import java.util.List;
import java.util.concurrent.Callable;


/**
 * @author mbechler
 *
 */
public interface SmbWatchHandle extends AutoCloseable, Callable<List<FileNotifyInformation>> {

    /**
     * Get the next set of changes
     * 
     * Will block until the server returns a set of changes that match the given filter. The file will be automatically
     * opened if it is not and should be closed with {@link #close()} when no longer
     * needed.
     * 
     * Closing the context should cancel a pending notify request, but that does not seem to work reliable in all
     * implementations.
     * 
     * Changes in between these calls (as long as the file is open) are buffered by the server, so iteratively calling
     * this method should provide all changes (size of that buffer can be adjusted through
     * {@link jcifs.Configuration#getNotifyBufferSize()}).
     * If the server cannot fulfill the request because the changes did not fit the buffer
     * it will return an empty list of changes.
     * 
     * @return changes since the last invocation
     * @throws SmbException
     */
    List<FileNotifyInformation> watch () throws SmbException;


    /**
     * {@inheritDoc}
     *
     * @see java.util.concurrent.Callable#call()
     */
    @Override
    List<FileNotifyInformation> call () throws SmbException;


    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    void close () throws SmbException;

}