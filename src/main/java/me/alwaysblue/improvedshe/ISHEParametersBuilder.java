package me.alwaysblue.improvedshe;

import java.security.SecureRandom;
import java.util.Random;

public class ISHEParametersBuilder {
    private int k0 = 4096;
    private int kL = 160;
    private int kr = 160;
    private int kM = 128;

    private Random random = new SecureRandom();
    private int primeCertainty = 40;

    public ISHEParametersBuilder() {
    }

    public ISHEParametersBuilder(int k0, int kL, int kr, int kM) {
        this.k0 = k0;
        this.kL = kL;
        this.kr = kr;
        this.kM = kM;
    }

    public ISHEParametersBuilder random(SecureRandom random) {
        this.random = random;
        return this;
    }

    public ISHEParametersBuilder primeCertainty(int certainty) {
        this.primeCertainty = certainty;
        return this;
    }

    public ISHEParametersBuilder k0(int k0) {
        this.k0 = k0;
        return this;
    }

    public ISHEParametersBuilder kL(int kL) {
        this.kL = kL;
        return this;
    }

    public ISHEParametersBuilder kr(int kr) {
        this.kr = kr;
        return this;
    }

    public ISHEParametersBuilder kM(int kM) {
        this.kM = kM;
        return this;
    }

    public ISHEParameters build() {
        return new ISHEParameters(k0, kL, kr, kM);
    }
}

