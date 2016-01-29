package jcifs.pac;


import jcifs.smb.SID;


public class PacGroup {

    private SID id;
    private int attributes;


    public PacGroup ( SID id, int attributes ) {
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
