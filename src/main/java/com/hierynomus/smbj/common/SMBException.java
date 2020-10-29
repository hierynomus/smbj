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
package com.hierynomus.smbj.common;

import com.hierynomus.protocol.commons.concurrent.ExceptionWrapper;

import java.io.IOException;

public class SMBException extends IOException {
    public static final ExceptionWrapper<SMBException> Wrapper = new ExceptionWrapper<SMBException>() {
        @Override
        public SMBException wrap(Throwable throwable) {
            if (throwable instanceof SMBException) {
                return (SMBException) throwable;
            } else {
                return new SMBException(throwable);
            }
        }
    };

    public SMBException(String message) {
        super(message);
    }

    public SMBException(Throwable t) {
        super(t);
    }
}
