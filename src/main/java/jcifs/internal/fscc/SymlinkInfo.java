package jcifs.internal.fscc;

public interface SymlinkInfo {


    /**
     *
     * @return symlink target
     */
    String getSubstituteName();

    /**
     *
     * @return human-readable name
     */
    String getPrintName();

    boolean isRelative();
}
