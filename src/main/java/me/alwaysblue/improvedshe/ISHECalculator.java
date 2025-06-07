package me.alwaysblue.improvedshe;

import java.math.BigInteger;

public class ISHECalculator {
    ISHEPublicParameters pp;

    ISHEPublicKey pk;

    public ISHECalculator(ISHEPublicParameters pp, ISHEPublicKey pk) {
        this.pp = pp;
        this.pk = pk;
    }

    public ISHECiphertext multiply(ISHECiphertext a, ISHECiphertext b) {
        int d = a.d() + b.d();
        BigInteger res = a.ciphertext().multiply(b.ciphertext());
        return new ISHECiphertext(res, d);
    }

    public ISHECiphertext multiply(ISHECiphertext a, BigInteger b) {
        int d = a.d();
        BigInteger res = a.ciphertext().multiply(b);
        return new ISHECiphertext(res, d);
    }

    public ISHECiphertext add(ISHECiphertext a, ISHECiphertext b) {
        int d = Math.abs(a.d() - b.d());
        if (d != 0) {
            ISHECiphertext ctOne = new ISHECiphertext(pk.one().ciphertext(), d);
            if (a.d() > b.d()) {
                ISHECiphertext m2 = multiply(b, ctOne);
                return add(a, m2);
            } else {
                ISHECiphertext m1 = multiply(a, ctOne);
                return add(m1, b);
            }
        }
        return new ISHECiphertext(a.ciphertext().add(b.ciphertext()), a.d());
    }

    public ISHECiphertext add(ISHECiphertext a, BigInteger b) {
        ISHECiphertext m2 = multiply(pk.one(), b);
        return new ISHECiphertext(a.ciphertext().add(m2.ciphertext()), a.d());
    }
}
