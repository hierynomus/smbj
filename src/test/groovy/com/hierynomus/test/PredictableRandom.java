package com.hierynomus.test;

import java.util.Random;

public class PredictableRandom extends Random {
    private byte[] randomBytes;
    private int idx;

    public void init(byte[] bytes) {
        this.randomBytes = bytes;
    }

    @Override
    public void nextBytes(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = randomBytes[(idx + i) % randomBytes.length];
        }
        idx = (idx + bytes.length) % randomBytes.length;
    }
}
