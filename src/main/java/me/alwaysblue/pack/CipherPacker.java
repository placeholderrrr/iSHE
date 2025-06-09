package me.alwaysblue.pack;

import me.alwaysblue.improvedshe.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class CipherPacker {
    private final ISHEPublicParameters pp;

    private final ISHEPublicKey pk;

    private final int plaintextBitLength;

    private final ISHECalculator calculator;

    public CipherPacker(ISHEPublicParameters pp, ISHEPublicKey pk, int plaintextBitLength) {
        this.pp = pp;
        this.pk = pk;
        this.plaintextBitLength = plaintextBitLength;
        this.calculator = new ISHECalculator(pp, pk);
    }

    public ISHECiphertext pack(List<ISHECiphertext> ciphertexts) {
        if (ciphertexts.isEmpty()) {
            throw new IllegalArgumentException("Cannot pack an empty list");
        }

        int n = ciphertexts.size();
        ISHECiphertext c = pk.zero();
        for (int i = 0; i < n; i++) {
            int powerOfTwo = i * plaintextBitLength;
            ISHECiphertext ct = ciphertexts.get(i);
            ISHECiphertext ct1 = calculator.multiply(ct, BigInteger.TWO.pow(powerOfTwo));
            c = calculator.add(c, ct1);
        }
        return c;
    }

    public List<BigInteger> unpack(ISHECiphertext c, int packNum, ISHESecretKey sk) {
        List<BigInteger> res = new ArrayList<>();
        BigInteger packedData = ISHE.decrypt(sk, pp, c);
        for (int i = 0; i < packNum; i++) {
            int shiftBits = plaintextBitLength * i;
            BigInteger plaintext = packedData.shiftRight(shiftBits).mod(BigInteger.TWO.pow(plaintextBitLength));
            res.add(plaintext);
        }

        return res;
    }
}
