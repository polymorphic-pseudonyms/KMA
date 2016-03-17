package nl.surfnet.polymorphic.kma;

import nl.surfnet.polymorphic.KMA;
import nl.surfnet.polymorphic.PPKeyPair;
import nl.surfnet.polymorphic.SystemParams;
import nl.surfnet.polymorphic.Util;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Base64;
import java.util.Properties;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Properties properties = new Properties();
        try {
            FileInputStream in = new FileInputStream("kma.properties");
            properties.load(in);
            in.close();

            Scanner scanner = new Scanner(System.in);
            System.out.print("SP:");
            String sp = scanner.nextLine().trim();
            while(sp.isEmpty()) {
                System.out.print("SP:");
                sp=scanner.nextLine().trim();
            }

            Base64.Decoder base64 = Base64.getDecoder();

            BigInteger x_k = new BigInteger(1, base64.decode(properties.getProperty("x_k")));
            byte[] D_k = base64.decode(properties.getProperty("D_k"));

            BigInteger closingKey = Util.random();
            while(closingKey.compareTo(SystemParams.getOrder()) > 0) {
                closingKey = Util.random();
            }

            KMA kma = new KMA(x_k, D_k);

            PPKeyPair keypair = kma.requestKeyPair(sp);

            Base64.Encoder enc = Base64.getEncoder();
            System.out.printf("public key:\n%s\nprivate key:\n%s\nclosing key:\n%s\n",
                    enc.encodeToString(keypair.getPublicKey().getEncoded(true)),
                    enc.encodeToString(keypair.getPrivateKey().toByteArray()),
                    enc.encodeToString(closingKey.toByteArray()));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
