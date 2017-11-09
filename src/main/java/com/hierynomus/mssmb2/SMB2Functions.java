/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.mssmb2;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static com.hierynomus.utils.Strings.join;
import static com.hierynomus.utils.Strings.split;

public class SMB2Functions {
    private static final byte[] EMPTY_BYTES = new byte[0];

    public static byte[] unicode(String s) {
        if (s == null) {
            return EMPTY_BYTES;
        } else {
            return s.getBytes(StandardCharsets.UTF_16LE);
        }
    }

    // TODO shouldn't this be moved into com.hierynomus.smbj.common.SmbPath?
    public static String resolveSymlinkTarget(String originalFileName, SMB2Error.SymbolicLinkError symlinkData) {
        int unparsedPathLength = symlinkData.getUnparsedPathLength();
        String unparsedPath = getSymlinkUnparsedPath(originalFileName, unparsedPathLength);
        String substituteName = symlinkData.getSubstituteName();

        String target;
        if (symlinkData.isAbsolute()) {
            target = substituteName + unparsedPath;
        } else {
            String parsedPath = getSymlinkParsedPath(originalFileName, unparsedPathLength);
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

    private static String getSymlinkParsedPath(String fileName, int unparsedPathLength) {
        byte[] fileNameBytes = SMB2Functions.unicode(fileName);
        return new String(fileNameBytes, 0, fileNameBytes.length - unparsedPathLength, StandardCharsets.UTF_16LE);
    }

    private static String getSymlinkUnparsedPath(String fileName, int unparsedPathLength) {
        byte[] fileNameBytes = SMB2Functions.unicode(fileName);
        return new String(fileNameBytes, fileNameBytes.length - unparsedPathLength, unparsedPathLength, StandardCharsets.UTF_16LE);
    }

    private static String normalizePath(String path) {
        List<String> parts = split(path, '\\');

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

        return join(parts, '\\');
    }
}
