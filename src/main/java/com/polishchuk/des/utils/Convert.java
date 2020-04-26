package com.polishchuk.des.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class Convert {
    private Convert() {
    }

    public static String binToHex(String bin) {
        return new BigInteger(bin, 2).toString(16);
    }

    public static String hexToBin(String hex) {
        return new BigInteger(hex, 16).toString(2);
    }

    public static String binToUTF(String bin) {
        // Convert back to String
        byte[] cipherTextBytes = new byte[bin.length()/8];
        for(int j = 0; j < cipherTextBytes.length; j++) {
            String temp = bin.substring(0, 8);
            byte b = (byte) Integer.parseInt(temp, 2);
            cipherTextBytes[j] = b;
            bin = bin.substring(8);
        }
        return new String(cipherTextBytes, StandardCharsets.UTF_8).trim();
    }

    public static String utfToBin(String utf) {
        // Convert to binary
        byte[] bytes = utf.getBytes(StandardCharsets.UTF_8);

        StringBuilder bin = new StringBuilder();
        for (int aByte : bytes) {
            int value = aByte;
            for (int j = 0; j < 8; j++) {
                bin.append((value & 128) == 0 ? 0 : 1);
                value <<= 1;
            }
        }
        return bin.toString();
    }
}
