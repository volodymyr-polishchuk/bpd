package com.polishchuk.des;

import com.polishchuk.des.utils.Constants;
import org.apache.commons.lang3.StringUtils;

import java.math.BigInteger;

public class DESImpl {

    public static String exchangeIPBytes(String bytes) {
        StringBuilder builder = new StringBuilder();
        for (int i : Constants.IP) {
            builder.append(bytes.charAt(i - 1));
        }
        return builder.toString();
    }

    public static BinaryParts splitBytes(String bytes, int bites) {
        BinaryParts binaryParts = new BinaryParts();
        binaryParts.left = bytes.substring(0, bites);
        binaryParts.right = bytes.substring(bites, bites * 2);
        return binaryParts;
    }

    public static String exchangePC1Bytes(String passwordBinary) {
        StringBuilder builder = new StringBuilder();
        for (int i : Constants.PC_1) {
            builder.append(passwordBinary.charAt(i - 1));
        }
        return builder.toString();
    }

    public static String shiftLeft(String data, int shift) {
        StringBuilder builder = new StringBuilder(data);
        for (int i = 0; i < shift; i++) {
            String first = builder.substring(0, 1);
            builder.deleteCharAt(0);
            builder.append(first);
        }
        return builder.toString();
    }

    public static String merge(String left, String right) {
        return left + right;
    }

    public static String exchangePC2Bytes(String data) {
        StringBuilder builder = new StringBuilder();
        for (int i : Constants.PC_2) {
            builder.append(data.charAt(i - 1));
        }
        return builder.toString();
    }

    public static String exchangeEBytes(String data) {
        StringBuilder builder = new StringBuilder();
        for (int i : Constants.g) {
            builder.append(data.charAt(i - 1));
        }
        return builder.toString();
    }

    public static String xor(String vector, String key) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < vector.length(); i++) {
            boolean l = vector.charAt(i) == '1';
            boolean r = key.charAt(i) == '1';
            builder.append(l == r ? '0' : '1');
        }
        return builder.toString();
    }

    public static String applySBlocks(String xoredVector) {
        String[] parts = xoredVector.split("(?<=\\G.{6})");
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < Constants.s.length; i++) {
            String part = parts[i];
            int row = Integer.parseInt("" + part.charAt(0) + part.charAt(5), 2);
            int col = Integer.parseInt(part.substring(1, 5), 2);
            int value = Constants.s[i][row][col];
            String s = BigInteger.valueOf(value).toString(2);
            builder.append(StringUtils.leftPad(s, 4, "0"));
        }
        return builder.toString();
    }

    public static String exchangePBlocks(String data) {
        StringBuilder builder = new StringBuilder();
        for (int i : Constants.P) {
            builder.append(data.charAt(i - 1));
        }
        return builder.toString();
    }

    public static String swap(String binary, int halfBytes) {
        return binary.substring(halfBytes) + binary.substring(0, halfBytes);
    }

    public static String exchangeIPiBytes(String data) {
        StringBuilder builder = new StringBuilder();
        for (int i : Constants.IPi) {
            builder.append(data.charAt(i - 1));
        }
        return builder.toString();
    }
}
