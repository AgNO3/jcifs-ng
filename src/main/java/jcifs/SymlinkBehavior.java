/*
 * © 2023 Moritz Bechler
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
 * Symlink behavior
 *
 */
public enum SymlinkBehavior {
    /**
     * Will throw a {@link jcifs.smb.SmbSymlinkException} containing the target information when
     * encountering a symlink
     */
    THROW,

    /**
     * Automatically resolve symlinks that are located on the same share
     */
    RESOLVE_SAME_SHARE
}
