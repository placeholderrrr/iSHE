import me.alwaysblue.improvedshe.*;
import me.alwaysblue.pack.CipherPacker;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class CipherPackerTest {
    private static ISHEParameters parameters;

    @BeforeClass
    public static void setUp() {
        long keyGenStart = System.currentTimeMillis();
        parameters = ISHE.keyGen(4096, 160, 160, 128);
//        parameters = ISHE.keyGen(1024, 80, 80, 30);
        long keyGenEnd = System.currentTimeMillis();

        long keyGenTime = keyGenEnd - keyGenStart;
        System.out.println("KeyGen time: " + keyGenTime + " ms");
        System.out.println(parameters);
    }

    @Test
    public void test2BitsPackAndUnpack() {
        testNBitsPackAndUnpack(2);
    }

    @Test
    public void test9BitsPackAndUnpack() {
        testNBitsPackAndUnpack(9);
    }

    private void testNBitsPackAndUnpack(int plaintextBitLength) {
        List<ISHECiphertext> ciphertexts = new ArrayList<>();
        List<BigInteger> plaintexts = new ArrayList<>();
        int certainty = 40;
        for (int i = 0; i < 10; i++) {
            BigInteger plaintext = new BigInteger(plaintextBitLength, certainty, new SecureRandom());
            ISHECiphertext ciphertext = ISHE.encrypt(parameters.secretKey(), parameters.publicParameters(), plaintext);
            ciphertexts.add(ciphertext);
            plaintexts.add(plaintext);
        }
        CipherPacker packer = new CipherPacker(parameters.publicParameters(), parameters.publicKey(), plaintextBitLength);
        ISHECiphertext ciphertext = packer.pack(ciphertexts);
        List<BigInteger> unpackedPlaintexts = packer.unpack(ciphertext, 10, parameters.secretKey());

        System.out.println(plaintexts);
        System.out.println(unpackedPlaintexts);

        // 添加断言验证
        for (int i = 0; i < plaintexts.size(); i++) {
            assert plaintexts.get(i).equals(unpackedPlaintexts.get(i)) : "解包的明文与原始明文不匹配，索引：" + i;
        }
    }
}
