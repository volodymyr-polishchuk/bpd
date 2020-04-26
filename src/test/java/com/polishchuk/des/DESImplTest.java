package com.polishchuk.des;

import com.polishchuk.des.utils.BinaryUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class DESImplTest {

    @Test
    public void test_getBinary() {
        String binary = BinaryUtils.getBinary("password");
        Assertions.assertEquals(
                "0111000001100001011100110111001101110111011011110111001001100100",
                binary
        );
    }

    @Test
    public void test_getBinary2() {
        String binary = BinaryUtils.getBinary("kost'and");
        Assertions.assertEquals(
                "0110101101101111011100110111010000100111011000010110111001100100",
                binary
        );
    }

    @Test
    public void test_binaryToString() {
        String result = BinaryUtils.binaryToString("0110101101101111011100110111010000100111011000010110111001100100");
        Assertions.assertEquals("kost'and", result);
    }

    @Test
    public void test_exchangeIPBytes() {
        String binary = "0110101101101111011100110111010000100111011000010110111001100100";
        String result = DESImpl.exchangeIPBytes(binary);

        String expectedResult = "1110111100001100110110100011011100000000111111110100001101010111";
        Assertions.assertEquals(expectedResult, result);
    }

    @Test
    public void test_splitToByteParts() {
        String result = "1110111100001100110110100011011100000000111111110100001101010111";

        BinaryParts binaryParts = DESImpl.splitBytes(result, 32);

        String right = "00000000111111110100001101010111";

        String left = "11101111000011001101101000110111";

        Assertions.assertEquals(left, binaryParts.left);
        Assertions.assertEquals(right, binaryParts.right);
    }

    @Test
    public void test_exchangePasswordBytes() {
        String passwordBinary = BinaryUtils.getBinary("password");
        String result = DESImpl.exchangePC1Bytes(passwordBinary);
        Assertions.assertEquals("00000000111111111111111101010111110010110000001000001101", result); // untrusted
    }

    @Test
    public void test_splitToByteParts28() {
        String in = "00000000110111111101111101010101110010110000000000001101";

        BinaryParts binaryParts = DESImpl.splitBytes(in, 28);

        String c0 = "0000000011011111110111110101";
        String d0 = "0101110010110000000000001101";

        Assertions.assertEquals(c0, binaryParts.left);
        Assertions.assertEquals(d0, binaryParts.right);
    }

    @Test
    public void test_shiftBytes() {
        String in = "0000000011011111110111110101";
        String result = DESImpl.shiftLeft(in, 1);
        Assertions.assertEquals("0000000110111111101111101010", result);
    }

    @Test
    public void test_shiftBytes2() {
        String in = "0101110010110000000000001101";
        String result = DESImpl.shiftLeft(in, 1);
        Assertions.assertEquals("1011100101100000000000011010", result);
    }

    @Test
    public void test_mergeBytes() {
        String c1 = "0000000110111111101111101010";
        String d1 = "1011100101100000000000011010";

        String result = DESImpl.merge(c1, d1);

        Assertions.assertEquals("00000001101111111011111010101011100101100000000000011010", result);
    }

    @Test
    public void test_exchangePC2Bytes() {
        String merged = "00000001101111111011111010101011100101100000000000011010";
        String result = DESImpl.exchangePC2Bytes(merged);
        Assertions.assertEquals("111000001010111001101110011001000010001001000111", result);
    }

    @Test
    public void test_exchangeEBytes() {
        String binary = BinaryUtils.getBinary("kost'and");
        BinaryParts binaryParts = DESImpl.splitBytes(binary, 32);
        String result = DESImpl.exchangeEBytes(binaryParts.right);
        Assertions.assertEquals("000100001110101100000010101101011100001100001000", result);
    }

    @Test
    public void test_SBlocks() {
        String xoredVector = "011000001011100110010000001111011011010011110010";

        String sBlockApplyed = DESImpl.applySBlocks(xoredVector);

        String expected = "01010010100100010001101100110110";

        Assertions.assertEquals(expected, sBlockApplyed);
    }

    @Test
    public void test_exchangePBlocks() {
        String in = "01010010100100010001101100111101";

        String result = DESImpl.exchangePBlocks(in);

        Assertions.assertEquals("11111110001000001010110100100010", result);
    }

    @Test
    public void test_xor2() {
        String in = "11111110001000001010110100100010";
        String left = "11101111000011001101101000110111";

        String result = DESImpl.xor(in, left);

        Assertions.assertEquals("00010001001011000111011100010101", result);
    }

    @Test
    public void test_swap() {
        String left = "11001100";
        String right = "10101010";

        String result = DESImpl.swap(left + right, left.length());
        Assertions.assertEquals("1010101011001100", result);
    }

    @Test
    public void test_exchangeIPi() {
        String afterSwapResult = "0001000100101100011101110001010100000000111111110100001101010111";

        String exchangedIPi = DESImpl.exchangeIPiBytes(afterSwapResult);

        Assertions.assertEquals("0110111100101110001101110011000001100111001101000010111000100000", exchangedIPi);
    }

    @Test
    public void test_xor() {
        String binary = BinaryUtils.getBinary("polishch");
        BinaryParts binaryParts = DESImpl.splitBytes(binary, 32);
        String vector = DESImpl.exchangeEBytes(binaryParts.right);

        String passwordBinary = BinaryUtils.getBinary("password");
        String exchangePC1Bytes = DESImpl.exchangePC1Bytes(passwordBinary);
        BinaryParts passwordParts = DESImpl.splitBytes(exchangePC1Bytes, 28);
        passwordParts.left = DESImpl.shiftLeft(passwordParts.left, 1);
        passwordParts.right = DESImpl.shiftLeft(passwordParts.right, 1);
        String merged = DESImpl.merge(passwordParts.left, passwordParts.right);
        String key = DESImpl.exchangePC2Bytes(merged);

        String xoredVector = DESImpl.xor(vector, key);
        String sBlockApplyed = DESImpl.applySBlocks(xoredVector);
        String exchangePBlocks = DESImpl.exchangePBlocks(sBlockApplyed);

        String rightPartOfFinalRound = DESImpl.xor(exchangePBlocks, binaryParts.left);
        String round16result = binaryParts.right + rightPartOfFinalRound;
        String afterSwapResult = DESImpl.swap(round16result, 32);
        String encryptedText = DESImpl.exchangeIPiBytes(afterSwapResult);

        Assertions.assertEquals("1100110011011101000000000011011010000101101010111111111100000101", encryptedText);
    }
}
