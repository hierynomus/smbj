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
package com.hierynomus.smbj.paths;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Error;
import com.hierynomus.mssmb2.SMB2Functions;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.session.Session;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static com.hierynomus.utils.Strings.join;
import static com.hierynomus.utils.Strings.split;

public class SymlinkPathResolver implements PathResolver {
    private PathResolver wrapped;
    private Set<NtStatus> states;

    public SymlinkPathResolver(PathResolver wrapped) {
        this.wrapped = wrapped;
        this.states = EnumSet.copyOf(wrapped.handledStates());
        this.states.add(NtStatus.STATUS_STOPPED_ON_SYMLINK);
    }

    @Override
    public SmbPath resolve(Session session, SMB2Packet responsePacket, SmbPath smbPath) throws PathResolveException {
        if (responsePacket.getHeader().getStatus() == NtStatus.STATUS_STOPPED_ON_SYMLINK) {
            SMB2Error.SymbolicLinkError symlinkData = getSymlinkErrorData(responsePacket.getError());
            if (symlinkData == null) {
                throw new PathResolveException(responsePacket.getHeader().getStatus(), "Create failed for " + smbPath + ": missing symlink data");
            }
            String target = resolveSymlinkTarget(smbPath.getPath(), symlinkData);
            return new SmbPath(smbPath.getHostname(), smbPath.getShareName(), target);
        }

        return wrapped.resolve(session, responsePacket, smbPath);
    }

    @Override
    public Set<NtStatus> handledStates() {
        return states;
    }

    private static SMB2Error.SymbolicLinkError getSymlinkErrorData(SMB2Error error) {
        if (error != null) {
            List<SMB2Error.SMB2ErrorData> errorData = error.getErrorData();
            for (SMB2Error.SMB2ErrorData errorDatum : errorData) {
                if (errorDatum instanceof SMB2Error.SymbolicLinkError) {
                    return ((SMB2Error.SymbolicLinkError) errorDatum);
                }
            }
        }
        return null;
    }

    private String resolveSymlinkTarget(String originalFileName, SMB2Error.SymbolicLinkError symlinkData) {
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

    private String getSymlinkParsedPath(String fileName, int unparsedPathLength) {
        byte[] fileNameBytes = SMB2Functions.unicode(fileName);
        return new String(fileNameBytes, 0, fileNameBytes.length - unparsedPathLength, StandardCharsets.UTF_16LE);
    }

    private String getSymlinkUnparsedPath(String fileName, int unparsedPathLength) {
        byte[] fileNameBytes = SMB2Functions.unicode(fileName);
        return new String(fileNameBytes, fileNameBytes.length - unparsedPathLength, unparsedPathLength, StandardCharsets.UTF_16LE);
    }

    private String normalizePath(String path) {
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
