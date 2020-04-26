package com.polishchuk.rsa;

import java.math.BigInteger;

public class RSAImpl {

    private BigInteger p;
    private BigInteger q;
    private BigInteger e;
    private BigInteger eulerFunction;
    private BigInteger d;

    public RSAImpl(int p, int q, int e) {
        this.p = BigInteger.valueOf(p);
        this.q = BigInteger.valueOf(q);
        this.e = BigInteger.valueOf(e);

        eulerFunction = (this.p.subtract(BigInteger.ONE)).multiply(this.q.subtract(BigInteger.ONE));
        while (eulerFunction.gcd(this.e).intValue() > 1) {
            this.e = this.e.add(new BigInteger("2"));
        }
        d = this.e.modInverse(eulerFunction);
    }

    public byte[] encrypt(byte ...data) {
        byte[] bytes = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            bytes[i] = processBlockWithPublicKey(data[i]);
        }
        return bytes;
    }

    public byte[] decrypt(byte ...encryptedData) {
        byte[] bytes = new byte[encryptedData.length];
        for (int i = 0; i < encryptedData.length; i++) {
            bytes[i] = processBlockWithPrivateKey(encryptedData[i]);
        }
        return bytes;
    }

    private BigInteger getN() {
        return p.multiply(q);
    }

    private byte processBlockWithPublicKey(int m) {
        return (byte) BigInteger.valueOf(m).pow(e.intValue()).mod(getN()).intValue();
    }

    private byte processBlockWithPrivateKey(int c) {
        return (byte) BigInteger.valueOf(c).pow(d.intValue()).mod(getN()).intValue();
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getEulerFunction() {
        return eulerFunction;
    }

    public BigInteger getD() {
        return d;
    }
}
