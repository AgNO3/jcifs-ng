package jcifs.smb;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbResource;

public class SmbSymlinkException extends SmbException {

    private final String target;
    private transient final CIFSContext context;

    public SmbSymlinkException(String target, CIFSContext ctx) {
        // TODO: transform to URL
        this.target = target;
        this.context = ctx;
    }


    public String getTarget() {
        return target;
    }

    public SmbResource getResource() throws CIFSException {
        return this.context.get(this.target);
    }
}
