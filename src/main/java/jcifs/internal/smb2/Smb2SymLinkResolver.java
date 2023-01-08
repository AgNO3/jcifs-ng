/*
 * © 2022 AgNO3 Gmbh & Co. KG
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
package jcifs.internal.smb2;

import java.nio.charset.Charset;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.util.Strings;

/**
 * Defines methods to resolve a symlink target path.
 * 
 * @author Gregory Bragg
 */
public class Smb2SymLinkResolver {

    private static Logger log = LoggerFactory.getLogger(Smb2SymLinkResolver.class);

    private Smb2ErrorDataFormat erdf = new Smb2ErrorDataFormat();

    public String parseSymLinkErrorData ( String symLinkPath, byte[] errorData ) throws SMBProtocolDecodingException {
        log.debug("SymLink Path -> {}", symLinkPath);

        int symLinkLength = erdf.readSymLinkErrorResponse(errorData);
        log.debug("SymLink Length -> {}", symLinkLength);

        log.debug("Absolute Path -> {}", erdf.isAbsolutePath());
        log.debug("Print Name -> {}", erdf.getPrintName());
        log.debug("Unparsed Path Length -> {}", erdf.getUnparsedPathLength());
        log.debug("Substitute Name -> {}", erdf.getSubstituteName());

        String targetPath = this.resolveSymLinkTarget(symLinkPath);
        log.debug("Target Path -> {}", targetPath);
        return targetPath;
    }


    private String resolveSymLinkTarget ( String originalFileName ) {
        int unparsedPathLength = erdf.getUnparsedPathLength();
        String unparsedPath = getSymLinkUnparsedPath(originalFileName, unparsedPathLength);
        String substituteName = erdf.getSubstituteName();

        String target;
        if (erdf.isAbsolutePath()) {
            target = substituteName + unparsedPath;
        } else {
            String parsedPath = getSymLinkParsedPath(originalFileName, unparsedPathLength);
            StringBuilder b = new StringBuilder();
            int startIndex = parsedPath.lastIndexOf("\\");
            if (startIndex != -1) {
                b.append(parsedPath, 0, startIndex);
                b.append('\\');
            }
            b.append(substituteName);
            b.append(unparsedPath);
            target = b.toString();
        }

        return normalizePath(target);
    }


    private String getSymLinkParsedPath ( String fileName, int unparsedPathLength ) {
        byte[] fileNameBytes = fileName.getBytes(Charset.forName("UTF-16LE"));
        return new String(fileNameBytes, 0, fileNameBytes.length - unparsedPathLength, Charset.forName("UTF-16LE"));
    }


    private String getSymLinkUnparsedPath ( String fileName, int unparsedPathLength ) {
        byte[] fileNameBytes = fileName.getBytes(Charset.forName("UTF-16LE"));
        return new String(fileNameBytes, fileNameBytes.length - unparsedPathLength, unparsedPathLength, Charset.forName("UTF-16LE"));
    }


    private String normalizePath ( String path ) {
        List<String> parts = Strings.split(path, '\\');

        for (int i = 0; i < parts.size(); ) {
            String s = parts.get(i);
            if (".".equals(s)) {
                parts.remove(i);
            } else if ("..".equals(s)) {
                if (i > 0) {
                    parts.remove(i--);
                }
                parts.remove(i);
            } else {
                i++;
            }
        }

        return Strings.join(parts, '\\');
    }

}
