package me.alwaysblue.improvedshe;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

public class ISHE {
    private static final int ENCRYPTION_DEFAULT_D = 1;

    private static final Random SECURE_RANDOM = new SecureRandom();

    public static ISHEParameters keyGen(int k0, int kL, int kr, int kM) {
        return new ISHEParameters(k0, kL, kr, kM);
    }

    public static ISHEParameters keyGen(int k0, int kL, int kr, int kM, Random random, int primeCertainty) {
        return new ISHEParameters(k0, kL, kr, kM, random, primeCertainty);
    }

    public static ISHECiphertext encrypt(ISHESecretKey sk, ISHEPublicParameters pp, BigInteger message) {
        Objects.requireNonNull(sk, "Secret key cannot be null");
        Objects.requireNonNull(pp, "Public parameters cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");

        BigInteger r = new BigInteger(pp.kr(), SECURE_RANDOM);
        BigInteger rPrime = new BigInteger(pp.k0(), SECURE_RANDOM);

        BigInteger term1 = r.multiply(sk.L()).add(message);
        BigInteger term2 = BigInteger.ONE.add(rPrime.multiply(sk.p()));
        BigInteger ciphertext = term1.multiply(term2).multiply(sk.s()).mod(pp.N());

        return new ISHECiphertext(ciphertext, ENCRYPTION_DEFAULT_D);
    }

    public static BigInteger decrypt(ISHESecretKey sk, ISHEPublicParameters pp, ISHECiphertext ct) {
        Objects.requireNonNull(sk, "Secret key cannot be null");
        Objects.requireNonNull(pp, "Public parameters cannot be null");
        Objects.requireNonNull(ct, "Ciphertext cannot be null");



        BigInteger modCt = ct.ciphertext().mod(pp.N());
        BigInteger sPowDModInverse = sk.s().pow(ct.d()).modInverse(pp.N());
        BigInteger middleVal = sPowDModInverse.multiply(modCt).mod(pp.N()).mod(sk.p()).mod(sk.L());
        if (middleVal.compareTo(sk.L().divide(BigInteger.TWO)) < 0) {
            return middleVal;
        } else {
            return sk.L().subtract(middleVal);
        }
    }
}
