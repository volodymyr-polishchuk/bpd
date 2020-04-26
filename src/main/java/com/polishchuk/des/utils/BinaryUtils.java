package com.polishchuk.des.utils;

import org.apache.commons.lang3.StringUtils;

import java.math.BigInteger;
import java.util.stream.Collectors;

public class BinaryUtils {

    public static String getBinary(String data) {
        return data.chars()
                .mapToLong(value -> value)
                .mapToObj(operand -> BigInteger.valueOf(operand).toString(2))
                .map(s -> StringUtils.leftPad(s, 8, '0'))
                .collect(Collectors.joining());
    }

    public static String binaryToString(String binary) {
        String[] split = binary.split("(?<=\\G.{8})");
        StringBuilder builder = new StringBuilder();
        for (String part : split) {
            char i = (char) Integer.parseInt(part, 2);
            builder.append(i);
        }
        return builder.toString();
    }
}
