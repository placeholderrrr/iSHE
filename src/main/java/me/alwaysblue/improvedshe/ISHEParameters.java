package me.alwaysblue.improvedshe;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class ISHEParameters {
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int PRIME_CERTAINTY = 40;

    /*
     * k0: 生成的大素数p 和 q 的比特长度，k0 的大小直接影响加密方案的安全性
     */
    private int k0;

    /*
     * kL: 私钥中随机数 L 的比特长度
     */
    private int kL;

    /*
     * kr: 随机数 r 的比特长度
     */
    private int kr;

    /*
     * kM: 消息空间的最大比特长度
     */
    private int kM;

    private ISHESecretKey sk;

    private ISHEPublicParameters pp;

    private BigInteger s;
    private BigInteger p;
    private BigInteger q;
    private BigInteger L;
    private BigInteger M;
    private BigInteger N;

    private ISHECiphertext zero;
    private ISHECiphertext zeroPrime;
    private ISHECiphertext one;

    public ISHEParameters(int k0, int kL, int kr, int kM) {
        this(k0, kL, kr, kM, RANDOM, PRIME_CERTAINTY);
    }

    public ISHEParameters(int k0, int kL, int kr, int kM, Random random, int primeCertainty) {
        if (k0 <= 0 || kL <= 0 || kr <= 0 || kM <= 0) {
            throw new IllegalArgumentException("所有比特长度必须大于0");
        }

        if (kM >= kL || kL != kr || kr >= k0) {
            throw new IllegalArgumentException("非法参数：需满足kM < kL = kr < k0");
        }

        this.k0 = k0;
        this.kL = kL;
        this.kr = kr;
        this.kM = kM;
        this.p = new BigInteger(k0, primeCertainty, random);
        this.q = new BigInteger(k0, primeCertainty, random);
        this.N = p.multiply(q);
        this.s = new BigInteger(this.N.bitLength(), primeCertainty, random);
        this.L = new BigInteger(kL, primeCertainty, random);
        this.M = BigInteger.valueOf(2).pow(kM - 1);
        this.sk = new ISHESecretKey(s, p, L);
        this.pp = new ISHEPublicParameters(k0, kr, M, N);
        try {
            this.zero = ISHE.encrypt(sk, pp, BigInteger.ZERO);
            this.zeroPrime = ISHE.encrypt(sk, pp, BigInteger.ZERO);
            this.one = ISHE.encrypt(sk, pp, BigInteger.ONE);
        } catch (Exception e) {
            throw new RuntimeException("初始化加密pk失败: " + e.getMessage(), e);
        }
    }

    public ISHESecretKey secretKey() {
        return sk;
    }

    public ISHEPublicParameters publicParameters() {
        return pp;
    }

    public ISHEPublicKey publicKey() {
        return new ISHEPublicKey(zero, zeroPrime, one);
    }

    @Override
    public String toString() {
        return "ISHEParameters{" +
                "k0=" + k0 +
                ", kL=" + kL +
                ", kr=" + kr +
                ", kM=" + kM +
                ", sk=" + sk +
                ", pp=" + pp +
                ", s=" + s +
                ", p=" + p +
                ", q=" + q +
                ", L=" + L +
                ", M=" + M +
                ", N=" + N +
                '}';
    }
}
