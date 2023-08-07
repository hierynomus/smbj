package com.hierynomus.smbj.testing;

import java.util.function.Consumer;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.Connection;

public class TestingUtils {
    public static void withConnectedClient(SmbConfig config, ConsumerWithError<Connection> f) throws Exception {
        try (SMBClient client = new SMBClient(config)) {
            try (Connection connection = client.connect("127.0.0.1")) {
                f.accept(connection);
            }
        }
    }

    public interface ConsumerWithError<T> {
        void accept(T val) throws Exception;
    }
}
