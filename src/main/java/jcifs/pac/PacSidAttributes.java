package jcifs.pac;

import jcifs.smb.SID;

public class PacSidAttributes {

    private SID id;
    private int attributes;


    public PacSidAttributes ( SID id, int attributes ) {
        super();
        this.id = id;
        this.attributes = attributes;
    }


    public SID getId () {
        return this.id;
    }


    public int getAttributes () {
        return this.attributes;
    }

}
