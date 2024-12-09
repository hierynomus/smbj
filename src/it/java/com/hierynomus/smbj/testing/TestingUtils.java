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
package com.hierynomus.smbj.testing;

import java.util.Random;
import java.util.stream.Stream;

import org.junit.jupiter.params.provider.Arguments;

import com.hierynomus.msfscc.fileinformation.FileStandardInformation;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.share.File;

public class TestingUtils {
    public static final Random RANDOM = new Random();

    public static final AuthenticationContext DEFAULT_AUTHENTICATION_CONTEXT = new AuthenticationContext("smbj",
            "smbj".toCharArray(), null);

    public static SmbConfig config(SMB2Dialect dialect, boolean encrypt, boolean signing) {
        return SmbConfig.builder().withDialects(dialect).withEncryptData(encrypt).withSigningRequired(signing)
                .withMultiProtocolNegotiate(true).withDfsEnabled(true).withSecurityProvider(new BCSecurityProvider())
                .build();
    }

    public static Stream<SmbConfig> allValidDialectCombinations() {
        return Stream.of(
                config(SMB2Dialect.SMB_2_1, false, false),
                config(SMB2Dialect.SMB_2_1, false, true),
                config(SMB2Dialect.SMB_3_0, false, false),
                config(SMB2Dialect.SMB_3_0, false, true),
                config(SMB2Dialect.SMB_3_0, true, false),
                config(SMB2Dialect.SMB_3_0, true, true),
                config(SMB2Dialect.SMB_3_0_2, false, false),
                config(SMB2Dialect.SMB_3_0_2, false, true),
                config(SMB2Dialect.SMB_3_0_2, true, false),
                config(SMB2Dialect.SMB_3_0_2, true, true),
                config(SMB2Dialect.SMB_3_1_1, false, false),
                config(SMB2Dialect.SMB_3_1_1, false, true),
                config(SMB2Dialect.SMB_3_1_1, true, false),
                config(SMB2Dialect.SMB_3_1_1, true, true));
    }

    public static Stream<Arguments> validConfigs() {
        return allValidDialectCombinations().map(c -> {
            return Arguments.of(c);
        });
    }

    public static Stream<Arguments> defaultTestingConfig() {
        return Stream.of(Arguments.of(config(SMB2Dialect.SMB_3_1_1, true, true)));
    }

    public static Stream<Arguments> dfsConfig() {
        return Stream.of(Arguments.of(config(SMB2Dialect.SMB_2_1, false, true)));
    }

    public static Stream<Arguments> loggedIn() {
        return allValidDialectCombinations().map(c -> {
            return Arguments.of(c, DEFAULT_AUTHENTICATION_CONTEXT);
        });
    }


    public static String randomFileName() {
        return "test-" + RANDOM.nextInt(1000000) + ".txt";
    }

    public static long endOfFile(File f) {
        return f.getFileInformation(FileStandardInformation.class).getEndOfFile();
    }

    public interface ConsumerWithError<T> {
        void accept(T val) throws Exception;
    }
}
