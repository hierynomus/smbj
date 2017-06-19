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
        super(diskShare, fileId, fileName);
    }

    public List<FileIdBothDirectoryInformation> list() throws SMBApiException {
        return list(FileIdBothDirectoryInformation.class);
    }

    public <F extends FileDirectoryQueryableInformation> List<F> list(Class<F> informationClass) throws SMBApiException {
        List<F> fileList = new ArrayList<>();
        Iterator<F> iterator = iterator(informationClass);
        while (iterator.hasNext()) {
            fileList.add(iterator.next());
        }
        return fileList;
    }


    @Override
    public Iterator<FileIdBothDirectoryInformation> iterator() {
        return iterator(FileIdBothDirectoryInformation.class);
    }

    public <F extends FileDirectoryQueryableInformation> Iterator<F> iterator(Class<F> informationClass) {
        return new DirectoryIterator<>(informationClass);
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
        private F next;

        DirectoryIterator(Class<F> informationClass) {
            decoder = FileInformationFactory.getDecoder(informationClass);
            currentIterator = queryDirectory(true);
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
                    currentIterator = queryDirectory(false);
                }
            }
            return null;
        }

        private Iterator<F> queryDirectory(boolean firstQuery) {
            DiskShare share = Directory.this.share;

            // Query Directory Request
            EnumSet<SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags> flags;
            if (firstQuery) {
                flags = EnumSet.of(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_RESTART_SCANS);
            } else {
                flags = EnumSet.noneOf(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.class);
            }

            FileInformationClass informationClass = decoder.getInformationClass();

            SMB2QueryDirectoryResponse qdResp = share.queryDirectory(fileId, flags, informationClass);

            NtStatus status = qdResp.getHeader().getStatus();

            if (status == NtStatus.STATUS_NO_MORE_FILES) {
                return null;
            } else {
                return FileInformationFactory.createFileInformationIterator(
                    qdResp.getOutputBuffer(),
                    decoder
                );
            }
        }
        @Override
        public void remove() {
            throw new UnsupportedOperationException();
        }
    }
}
