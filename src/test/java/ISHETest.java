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
        parameters = ISHE.keyGen(4096, 160, 160, 128);
//        parameters = ISHE.keyGen(1024, 80, 80, 30);
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
    public void testCiphertextMulPlaintext() {
        ISHECiphertext ct1 = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), BigInteger.valueOf(123));
        ISHECiphertext res = calculator.multiply(ct1, BigInteger.valueOf(2));
        BigInteger pt = ISHE.decrypt(parameters.secretKey(), parameters.publicParameters(), res);
        assertEquals(BigInteger.valueOf(246), pt);
    }
}
