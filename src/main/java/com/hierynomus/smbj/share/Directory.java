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
package com.hierynomus.smbj.share;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.fileinformation.FileDirectoryQueryableInformation;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.msfscc.fileinformation.FileInformation;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.SMB2QueryDirectoryRequest;
import com.hierynomus.mssmb2.messages.SMB2QueryDirectoryResponse;

import java.util.*;

public class Directory extends DiskEntry implements Iterable<FileIdBothDirectoryInformation> {
    Directory(SMB2FileId fileId, DiskShare diskShare, String fileName) {
        super(fileId, diskShare, fileName);
    }

    /**
     * Equivalent to calling {@link #list(Class, String) list(FileIdBothDirectoryInformation.class, null)}.
     *
     * @see #list(Class, String)
     */
    public List<FileIdBothDirectoryInformation> list() throws SMBApiException {
        return list(FileIdBothDirectoryInformation.class);
    }

    /**
     * Equivalent to calling {@link #list(Class, String) list(informationClass, null)}.
     *
     * @see #list(Class, String)
     */
    public <F extends FileDirectoryQueryableInformation> List<F> list(Class<F> informationClass) throws SMBApiException {
        return list(informationClass, null);
    }

    /**
     * Calls {@link #iterator(Class, String) iterator(FileIdBothDirectoryInformation.class, null)} and collects
     * the contents of the returned iterator in a list.
     *
     * @see #iterator(Class, String)
     */
    public <F extends FileDirectoryQueryableInformation> List<F> list(Class<F> informationClass, String searchPattern) {
        List<F> fileList = new ArrayList<>();
        Iterator<F> iterator = iterator(informationClass, searchPattern);
        while (iterator.hasNext()) {
            fileList.add(iterator.next());
        }
        return fileList;
    }

    /**
     * Equivalent to calling {@link #iterator(Class, String) iterator(FileIdBothDirectoryInformation.class, null)}.
     *
     * @see #iterator(Class, String)
     */
    @Override
    public Iterator<FileIdBothDirectoryInformation> iterator() {
        return iterator(FileIdBothDirectoryInformation.class);
    }

    /**
     * Equivalent to calling {@link #iterator(Class, String) iterator(informationClass, null)}.
     *
     * @see #iterator(Class, String)
     */
    public <F extends FileDirectoryQueryableInformation> Iterator<F> iterator(Class<F> informationClass) {
        return iterator(informationClass, null);
    }

    /**
     * Returns an iterator of the contents of this directory.
     * <p>
     * The optional searchPattern parameter can contain the name of a file (or multiple files, if wildcards are used)
     * within this directory. When it is not <code>null</code> only files whose names match the search pattern string
     * are included in the resulting iterator. When it is <code>null</code> all files are included.
     * <p>
     * Two wild card characters are supported in the search pattern. The "?" (question mark) character matches a single
     * character. If a search pattern contains one or more "?" characters, then exactly that number of characters is
     * matched by the wildcards. For example, the criterion "??x" matches "abx" but not "abcx" or "ax", because the two
     * file names do not have enough characters preceding the literal. When a file name criterion has "?" characters
     * trailing a literal, then the match is made with specified number of characters or less. For example, the
     * criterion "x??" matches "xab", "xa", and "x", but not "xabc". If only "?" characters are present in the file name
     * selection criterion, then the match is made as if the criterion contained "?" characters trailing a literal.
     * The "*" (asterisk) character matches an entire file name. A null or empty specification criterion also selects
     * all file names. For example, "*.abc" or ".abc" match any file with an extension of "abc". "*.*", "*", or empty
     * string("") match all files in a directory.
     */
    public <F extends FileDirectoryQueryableInformation> Iterator<F> iterator(Class<F> informationClass, String searchPattern) {
        return new DirectoryIterator<>(informationClass, searchPattern);
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    @Override
    public String toString() {
        return String.format("Directory{fileId=%s, fileName='%s'}", fileId, fileName);
    }

    private class DirectoryIterator<F extends FileDirectoryQueryableInformation> implements Iterator<F> {
        private final FileInformation.Decoder<F> decoder;
        private Iterator<F> currentIterator;
        private byte[] currentBuffer;
        private F next;
        private String searchPattern;

        DirectoryIterator(Class<F> informationClass, String searchPattern) {
            decoder = FileInformationFactory.getDecoder(informationClass);
            this.searchPattern = searchPattern;
            queryDirectory(true);
            this.next = prepareNext();
        }

        @Override
        public boolean hasNext() {
            return next != null;
        }

        @Override
        public F next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }

            F fileInfo = this.next;
            this.next = prepareNext();
            return fileInfo;
        }

        private F prepareNext() {
            while (currentIterator != null) {
                if (currentIterator.hasNext()) {
                    return currentIterator.next();
                } else {
                    queryDirectory(false);
                }
            }
            return null;
        }

        private void queryDirectory(boolean firstQuery) {
            DiskShare share = Directory.this.share;

            // Query Directory Request
            EnumSet<SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags> flags;
            if (firstQuery) {
                flags = EnumSet.of(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_RESTART_SCANS);
            } else {
                flags = EnumSet.noneOf(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.class);
            }

            FileInformationClass informationClass = decoder.getInformationClass();

            SMB2QueryDirectoryResponse qdResp = share.queryDirectory(fileId, flags, informationClass, searchPattern);

            NtStatus status = qdResp.getHeader().getStatus();
            byte[] buffer = qdResp.getOutputBuffer();

            // The macOS SMB server doesn't always send a STATUS_NO_MORE_FILES response. Instead it keeps on sending
            // an identical response back. Detect if the response is identical to the previous one and abort the loop
            // if that's the case.
            // Additionally, STATUS_NO_SUCH_FILE is being returned when searchPattern does not match any files
            if (status == NtStatus.STATUS_NO_MORE_FILES || status == NtStatus.STATUS_NO_SUCH_FILE || (currentBuffer != null && Arrays.equals(currentBuffer, buffer))) {
                currentIterator = null;
                currentBuffer = null;
            } else {
                currentBuffer = buffer;
                currentIterator = FileInformationFactory.createFileInformationIterator(currentBuffer, decoder);
            }
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException();
        }
    }
}
