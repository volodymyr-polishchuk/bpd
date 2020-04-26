package com.polishchuk.rsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class RSAImplTest {

    @Test
    public void test_polishchuk() {
        RSAImpl rsa = new RSAImpl(7, 19, 23);
        byte[] encrypted = rsa.encrypt("poli".getBytes(StandardCharsets.US_ASCII));
        byte[] decrypt = rsa.decrypt(encrypted);
        Assertions.assertArrayEquals("poli".getBytes(StandardCharsets.US_ASCII), decrypt);
    }

    @Test
    public void test_encrypt() {
        RSAImpl rsa = new RSAImpl(7, 19, 23);
        byte[] encrypt = rsa.encrypt(new byte[]{107, 111, 115, 116});
        Assertions.assertArrayEquals(new byte[]{46, 118, 96, 51}, encrypt);
    }

    @Test
    public void test_fe() {
        RSAImpl rsa = new RSAImpl(7, 19, 23);
        Assertions.assertEquals(47, rsa.getD().intValue());
    }

    @Test
    public void test_decrypt() {
        RSAImpl rsa = new RSAImpl(7, 19, 23);
        byte[] decrypt = rsa.decrypt(new byte[]{46, 118, 96, 51});
        Assertions.assertArrayEquals(new byte[]{107, 111, 115, 116}, decrypt);
    }
}
