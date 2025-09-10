import me.alwaysblue.improvedshe.ISHE;
import me.alwaysblue.improvedshe.ISHECalculator;
import me.alwaysblue.improvedshe.ISHECiphertext;
import me.alwaysblue.improvedshe.ISHEParameters;
import org.junit.*;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class ISHETest {

    private static ISHEParameters parameters;

    private static ISHECalculator calculator;

    @BeforeClass
    public static void setUp() {
        long keyGenStart = System.currentTimeMillis();
        // parameters = ISHE.keyGen(4096, 160, 160, 128);
        parameters = ISHE.keyGen(1024, 80, 80, 30);
        long keyGenEnd = System.currentTimeMillis();

        long keyGenTime = keyGenEnd - keyGenStart;
        System.out.println("KeyGen time: " + keyGenTime + " ms");
        System.out.println(parameters);

        calculator = new ISHECalculator(parameters.publicParameters(), parameters.publicKey());
    }

    @Test
    public void testEncAndDec() {
        System.out.println("Running testEncAndDec...");

        long encStart = System.currentTimeMillis();
        ISHECiphertext ct1 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(123));
        long encEnd = System.currentTimeMillis();

        System.out.println("Enc time: " + (encEnd - encStart) + " ms");
        System.out.println(ct1);

        long decStart = System.currentTimeMillis();
        BigInteger pt = ISHE.decrypt(parameters.secretKey(), parameters.publicParameters(), ct1);
        long decEnd = System.currentTimeMillis();

        System.out.println("Dec time: " + (decEnd - decStart) + " ms");

        assertEquals(BigInteger.valueOf(123), pt);
    }

    @Test
    public void testCiphertextAddCipherText() {
        ISHECiphertext ct1 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(123));
        ISHECiphertext ct2 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(456));
        ISHECiphertext res = calculator.add(ct1, ct2);
        BigInteger pt = ISHE.decrypt(parameters.secretKey(), parameters.publicParameters(), res);
        assertEquals(BigInteger.valueOf(579), pt);
    }

    @Test
    public void testCiphertextAddPlaintext() {
        ISHECiphertext ct1 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(123));
        ISHECiphertext res = calculator.add(ct1, BigInteger.valueOf(456));
        BigInteger pt = ISHE.decrypt(parameters.secretKey(), parameters.publicParameters(), res);
        assertEquals(BigInteger.valueOf(579), pt);
    }

    @Test
    public void testCiphertextMulCipherText() {
        ISHECiphertext ct1 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(123));
        ISHECiphertext ct2 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(2));
        ISHECiphertext res = calculator.multiply(ct1, ct2);
        BigInteger pt = ISHE.decrypt(parameters.secretKey(), parameters.publicParameters(), res);
        assertEquals(BigInteger.valueOf(246), pt);
    }

    @Test
    public void testCiphertextMulCipherText1() {
        ISHECiphertext ct1 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(111));
        ISHECiphertext ct2 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(2));
        ISHECiphertext ct3 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(2));
        ISHECiphertext ct4 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(2));
        ISHECiphertext ct5 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(2));
        ISHECiphertext ct6 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(2));
        ISHECiphertext ct7 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(2));
        ISHECiphertext res = calculator.multiply(ct1, ct2);
        res = calculator.multiply(res, ct3);
        res = calculator.multiply(res, ct4);
        res = calculator.multiply(res, ct5);
        res = calculator.multiply(res, ct6);
        res = calculator.multiply(res, ct7);
        BigInteger pt = ISHE.decrypt(parameters.secretKey(), parameters.publicParameters(), res);
        assertEquals(BigInteger.valueOf(7104), pt);
    }

    @Test
    public void testCiphertextMulPlaintext() {
        ISHECiphertext ct1 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(123));
        ISHECiphertext res = calculator.multiply(ct1, BigInteger.valueOf(2));
        BigInteger pt = ISHE.decrypt(parameters.secretKey(), parameters.publicParameters(), res);
        assertEquals(BigInteger.valueOf(246), pt);
    }

    @Test
    public void testPerformanceEncAndDec() {
        System.out.println("Running testPerformanceEncAndDec...");

        int iterations = 10000;
        BigInteger plaintext = BigInteger.valueOf(123);

        // 加密性能测试
        long encStart = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), plaintext);
        }
        long encEnd = System.currentTimeMillis();
        long encTime = encEnd - encStart;
        System.out.println("Total encryption time for " + iterations + " iterations: " + encTime + " ms");
        System.out.println("Average encryption time per operation: " + (double) encTime / iterations + " ms");

        // 解密性能测试
        // 先加密一次获取密文用于后续的解密测试
        ISHECiphertext ct = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), plaintext);

        long decStart = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            ISHE.decrypt(parameters.secretKey(), parameters.publicParameters(), ct);
        }
        long decEnd = System.currentTimeMillis();
        long decTime = decEnd - decStart;
        System.out.println("Total decryption time for " + iterations + " iterations: " + decTime + " ms");
        System.out.println("Average decryption time per operation: " + (double) decTime / iterations + " ms");
    }

}
