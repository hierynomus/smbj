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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.share.Share;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

public class SMB2Functions {
    private static final byte[] EMPTY_BYTES = new byte[0];

    public static byte[] unicode(String s) {
        if (s == null) {
            return EMPTY_BYTES;
        } else {
            return s.getBytes(StandardCharsets.UTF_16LE);
        }
    }

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

    public static String normalizePath(String path) {
        List<String> parts = new ArrayList<>();
        int start = 0;
        while (start < path.length()) {
            int next = path.indexOf('\\', start);
            if (next == -1) {
                parts.add(path.substring(start));
                start = path.length();
            } else {
                parts.add(path.substring(start, next));
                start = next + 1;
            }
        }

        for (int i = 0; i < parts.size(); ) {
            String s = parts.get(i);
            if (".".equals(s)) {
                parts.remove(i);
            } else if ("..".equals(s)) {
                parts.remove(i--);
                if (i >= 0) {
                    parts.remove(i);
                }
            } else {
                i++;
            }
        }

        StringBuilder normalized = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) {
                normalized.append('\\');
            }
            normalized.append(parts.get(i));
        }
        return normalized.toString();
    }
}
