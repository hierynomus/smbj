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
package com.hierynomus.msfscc.fileinformation;

public class FileAllInformation implements FileQueryableInformation {
    private FileBasicInformation basicInformation;
    private FileStandardInformation standardInformation;
    private FileInternalInformation internalInformation;
    private FileEaInformation eaInformation;
    private FileAccessInformation accessInformation;
    private FilePositionInformation positionInformation;
    private FileModeInformation modeInformation;
    private FileAlignmentInformation alignmentInformation;
    private String nameInformation;

    FileAllInformation(FileBasicInformation basicInformation, FileStandardInformation standardInformation, FileInternalInformation internalInformation, FileEaInformation eaInformation, FileAccessInformation accessInformation, FilePositionInformation positionInformation, FileModeInformation modeInformation, FileAlignmentInformation alignmentInformation, String nameInformation) {
        this.basicInformation = basicInformation;
        this.standardInformation = standardInformation;
        this.internalInformation = internalInformation;
        this.eaInformation = eaInformation;
        this.accessInformation = accessInformation;
        this.positionInformation = positionInformation;
        this.modeInformation = modeInformation;
        this.alignmentInformation = alignmentInformation;
        this.nameInformation = nameInformation;
    }

    public FileBasicInformation getBasicInformation() {
        return basicInformation;
    }

    public FileStandardInformation getStandardInformation() {
        return standardInformation;
    }

    public FileInternalInformation getInternalInformation() {
        return internalInformation;
    }

    public FileEaInformation getEaInformation() {
        return eaInformation;
    }

    public FileAccessInformation getAccessInformation() {
        return accessInformation;
    }

    public FilePositionInformation getPositionInformation() {
        return positionInformation;
    }

    public FileModeInformation getModeInformation() {
        return modeInformation;
    }

    public FileAlignmentInformation getAlignmentInformation() {
        return alignmentInformation;
    }

    public String getNameInformation() {
        return nameInformation;
    }
}
