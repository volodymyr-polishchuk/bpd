package com.polishchuk.des;

import com.polishchuk.des.utils.Constants;
import com.polishchuk.des.utils.Convert;

public class DES {

    private long[] K;

    public DES() {

        // First index is garbage value, loops operating on this should start with index = 1
        K = new long[17];

    }

    /**
     * Encrypt a string message with the DES block cipher
     * @param key
     * @param plaintext
     * @return
     */
    public String encrypt(String key, String plaintext) {

        // Build the key schedule
        buildKeySchedule(hash(key));

        String binPlaintext = plaintext;

        // Add padding if necessary
        int remainder = binPlaintext.length() % 64;
        if (remainder != 0) {
            for (int i = 0; i < (64 - remainder); i++)
                binPlaintext = "0" + binPlaintext;
        }

        // Separate binary plaintext into blocks
        String[] binPlaintextBlocks = new String[binPlaintext.length()/64];
        int offset = 0;
        for (int i = 0; i < binPlaintextBlocks.length; i++) {
            binPlaintextBlocks[i] = binPlaintext.substring(offset, offset+64);
            offset += 64;
        }

        String[] binCiphertextBlocks = new String[binPlaintext.length()/64];

        // Encrypt the blocks
        for (int i = 0; i < binCiphertextBlocks.length; i++)
            try {
                binCiphertextBlocks[i] = encryptBlock(binPlaintextBlocks[i]);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        // Build the ciphertext binary string from the blocks
        String binCiphertext = "";
        for (int i = 0; i < binCiphertextBlocks.length; i++)
            binCiphertext += binCiphertextBlocks[i];

        // Destroy key schedule
        for (int i=0;i<K.length;i++)
            K[i] = 0;


        return binCiphertext;
    }

    /**
     * Decrypt a string message with the DES block cipher
     * @param key : String - the key to decrypt with
     * @param plaintext : String - Hex string to decrypt
     * @return Plaintext message string
     */
    public String decrypt(String key, String plaintext) {

        // Build the key schedule
        buildKeySchedule(hash(key));

        String binPlaintext = null;

        binPlaintext = plaintext;

        // Add padding if necessary
        int remainder = binPlaintext.length() % 64;
        if (remainder != 0) {
            for (int i = 0; i < (64 - remainder); i++)
                binPlaintext = "0" + binPlaintext;
        }

        // Separate binary plaintext into blocks
        String[] binPlaintextBlocks = new String[binPlaintext.length()/64];
        int offset = 0;
        for (int i = 0; i < binPlaintextBlocks.length; i++) {
            binPlaintextBlocks[i] = binPlaintext.substring(offset, offset+64);
            offset += 64;
        }

        String[] binCiphertextBlocks = new String[binPlaintext.length()/64];

        // Encrypt the blocks
        for (int i = 0; i < binCiphertextBlocks.length; i++) {
            try {
                binCiphertextBlocks[i] = decryptBlock(binPlaintextBlocks[i]);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        // Build the ciphertext binary string from the blocks
        String binCiphertext = "";
        for (int i = 0; i < binCiphertextBlocks.length; i++)
            binCiphertext += binCiphertextBlocks[i];

        // Destroy key schedule
        for (int i=0;i<K.length;i++)
            K[i] = 0;

        return binCiphertext;
    }

    public String encryptBlock(String plaintextBlock) throws Exception {
        int length = plaintextBlock.length();
        if (length != 64)
            throw new RuntimeException("Input block length is not 64 bits!");

        //Initial permutation
        String out = "";
        for (int i = 0; i < Constants.IP.length; i++) {
            out = out + plaintextBlock.charAt(Constants.IP[i] - 1);
        }

        String mL = out.substring(0, 32);
        String mR = out.substring(32);

        for (int i = 0; i < 16; i++) {

            // 48-bit current key
            String curKey = Long.toBinaryString(K[i+1]);
            while(curKey.length() < 48)
                curKey = "0" + curKey;

            // Get 32-bit result from f with m1 and ki
            String fResult = f(mR, curKey);

            // XOR m0 and f
            long f = Long.parseLong(fResult, 2);
            long cmL = Long.parseLong(mL, 2);

            long m2 = cmL ^ f;
            String m2String = Long.toBinaryString(m2);

            while(m2String.length() < 32)
                m2String = "0" + m2String;

            mL = mR;
            mR = m2String;
        }

        String in = mR + mL;
        String output = "";
        for (int i = 0; i < Constants.IPi.length; i++) {
            output = output + in.charAt(Constants.IPi[i] - 1);
        }

        return output;
    }

    public String decryptBlock(String plaintextBlock) throws RuntimeException {
        int length = plaintextBlock.length();
        if (length != 64)
            throw new RuntimeException("Input block length is not 64 bits!");

        //Initial permutation
        String out = "";
        for (int i = 0; i < Constants.IP.length; i++) {
            out = out + plaintextBlock.charAt(Constants.IP[i] - 1);
        }

        String mL = out.substring(0, 32);
        String mR = out.substring(32);

        for (int i = 16; i > 0; i--) {

            // 48-bit current key
            String curKey = Long.toBinaryString(K[i]);
            while(curKey.length() < 48)
                curKey = "0" + curKey;

            // Get 32-bit result from f with m1 and ki
            String fResult = f(mR, curKey);

            // XOR m0 and f
            long f = Long.parseLong(fResult, 2);
            long cmL = Long.parseLong(mL, 2);

            long m2 = cmL ^ f;
            String m2String = Long.toBinaryString(m2);

            while(m2String.length() < 32)
                m2String = "0" + m2String;

            mL = mR;
            mR = m2String;
        }

        String in = mR + mL;
        String output = "";
        for (int i = 0; i < Constants.IPi.length; i++) {
            output = output + in.charAt(Constants.IPi[i] - 1);
        }

        return output;
    }

    /**
     * Hash Function from user <b>sfussenegger</b> on stackoverflow
     *
     * @param string : String to hash
     * @return 64-bit long hash value
     * @source http://stackoverflow.com/questions/1660501/what-is-a-good-64bit-hash-function-in-java-for-textual-strings
     */

    // adapted from String.hashCode()
    public static long hash(String string) {
        long h = 1125899906842597L; // prime
        int len = string.length();

        for (int i = 0; i < len; i++) {
            h = 31*h + string.charAt(i);
        }
        return h;
    }

    public void buildKeySchedule(long key) {

        // Convert long value to 64bit binary string
        String binKey = Long.toBinaryString(key);

        // Add leading zeros if not at key length for ease of computations
        while (binKey.length() < 64)
            binKey = "0" + binKey;

        // For the 56-bit permuted key
        String binKey_PC1 = "";

        // Apply Permuted Choice 1 (64 -> 56 bit)
        for (int i = 0; i < Constants.PC_1.length; i++)
            binKey_PC1 = binKey_PC1 + binKey.charAt(Constants.PC_1[i]-1);

        String sL, sR;
        int iL, iR;

        // Split permuted string in half | 56/2 = 28
        sL = binKey_PC1.substring(0, 28);
        sR = binKey_PC1.substring(28);

        // Parse binary strings into integers for shifting
        iL = Integer.parseInt(sL, 2);
        iR = Integer.parseInt(sR, 2);

        // Build the keys (Start at index 1)
        for (int i = 1; i < K.length; i++) {

            // Perform left shifts according to key shift array
            iL = Integer.rotateLeft(iL, Constants.KEY_SHIFTS[i]);
            iR = Integer.rotateLeft(iR, Constants.KEY_SHIFTS[i]);

            // Merge the two halves
            long merged = ((long)iL << 28) + iR;

            // 56-bit merged
            String sMerged = Long.toBinaryString(merged);

            // Fix length if leading zeros absent
            while (sMerged.length() < 56)
                sMerged = "0" + sMerged;

            // For the 56-bit permuted key
            String binKey_PC2 = "";

            // Apply Permuted Choice 2 (56 -> 48 bit)
            for (int j = 0; j < Constants.PC_2.length; j++)
                binKey_PC2 = binKey_PC2 + sMerged.charAt(Constants.PC_2[j]-1);

            // Set the 48-bit key
            K[i] = Long.parseLong(binKey_PC2, 2);
        }
    }


    /**
     * Feistel function in DES algorithm specified in FIPS Pub 46
     * @param mi : String - 32-bit message binary string
     * @param key : String - 48-bit key binary string
     * @return 32-bit output string
     */
    public static String f(String mi, String key) {

        // Expansion function g (named E in fips pub 46)
        String gMi = "";
        for (int i = 0; i < Constants.g.length; i++) {
            gMi = gMi + mi.charAt(Constants.g[i] - 1);
        }

        long m =  Long.parseLong(gMi, 2);
        long k = Long.parseLong(key, 2);

        // XOR expanded message block and key block (48 bits)
        Long result = m ^ k;

        String bin = Long.toBinaryString(result);
        // Making sure the string is 48 bits
        while (bin.length() < 48) {
            bin = "0" + bin;
        }

        // Split into eight 6-bit strings
        String[] sin = new String[8];
        for (int i = 0; i < 8; i++) {
            sin[i] = bin.substring(0, 6);
            bin = bin.substring(6);
        }


        // Do S-Box calculations
        String[] sout = new String[8];
        for (int i = 0 ; i < 8; i++) {
            int[][] curS = Constants.s[i];
            String cur = sin[i];

            // Get binary values
            int row = Integer.parseInt(cur.charAt(0) + "" + cur.charAt(5), 2);
            int col = Integer.parseInt(cur.substring(1, 5), 2);

            // Do S-Box table lookup
            sout[i] = Integer.toBinaryString(curS[row][col]);

            // Make sure the string is 4 bits
            while(sout[i].length() < 4)
                sout[i] = "0" + sout[i];

        }

        // Merge S-Box outputs into one 32-bit string
        String merged = "";
        for (int i = 0; i < 8; i++) {
            merged = merged + sout[i];
        }

        // Apply Permutation P
        String mergedP = "";
        for (int i = 0; i < Constants.P.length; i++) {
            mergedP = mergedP + merged.charAt(Constants.P[i] - 1);
        }

        return mergedP;
    }

    public static void main(String[] args) {

        DES des = new DES();

        boolean enc = true;
        String key1 = null, key2 = null, key3 = null, message = null, result = null;

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-k1"))
                key1 = args[++i];
            else if (args[i].equals("-k2"))
                key2 = args[++i];
            else if (args[i].equals("-k3"))
                key3 = args[++i];
            else if (args[i].equals("-m"))
                message = args[++i];
            else if (args[i].equals("-d"))
                enc = false;
        }

        if (enc) {
            if (message == null) {
                System.out.println("No message given to encrypt. Exiting..");
                System.exit(0);
            } else if (key1 == null) {
                System.out.println("Improper use of key arguments. Exiting..");
                System.exit(0);
            }

            if (key2 == null) {
                if (key3 != null) {
                    System.out.println("Improper use of key arguments. Exiting..");
                    System.exit(0);
                }
                result = des.encrypt(key1, Convert.utfToBin(message));
                System.out.println(Convert.binToHex(result));
            } else {
                if (key3 == null) {
                    System.out.println("Improper use of key arguments. Exiting..");
                    System.exit(0);
                }
                result = des.encrypt(key3, des.decrypt(key2, des.encrypt(key1, Convert.utfToBin(message))));
                System.out.println(Convert.binToHex(result));
            }
        } else {
            if (message == null) {
                System.out.println("No data given to decrypt. Exiting..");
                System.exit(0);
            } else if (key1 == null) {
                System.out.println("Improper use of key arguments. Exiting..");
                System.exit(0);
            }

            if (key2 == null) {
                if (key3 != null) {
                    System.out.println("Improper use of key arguments. Exiting..");
                    System.exit(0);
                }
                result = des.decrypt(key1, Convert.hexToBin(message));
                System.out.println(Convert.binToUTF(result));
            } else {
                if (key3 == null) {
                    System.out.println("Improper use of key arguments. Exiting..");
                    System.exit(0);
                }
                result = des.decrypt(key1, des.encrypt(key2, des.decrypt(key3, Convert.hexToBin(message))));
                System.out.println(Convert.binToUTF(result));
            }
        }

    }

}
