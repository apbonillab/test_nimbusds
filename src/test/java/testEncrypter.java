import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import net.minidev.json.JSONObject;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;

public class testEncrypter {
    public class RsaKeyDto{
        String n;
        String d;
        String e;
    }
    @Test
    public void pruebas() throws NoSuchAlgorithmException, JOSEException, ParseException, InvalidKeySpecException {
        RsaKeyDto rsaKeyDto = new RsaKeyDto();
        rsaKeyDto.n = "00:c5:3a:3f:fe:55:fc:0a:72:14:bf:6e:20:50:ee:b2:70:d7:29:98:34:9c:1e:c3:17:da:90:2a:79:f0:a6:84:4c:7a:ba:53:94:58:d7:44:a2:50:8f:5f:8a:5c:fa:6e:4a:2e:6b:55:bb:a6:10:eb:67:b0:65:6c:d1:3a:05:30:dc:ba:f7:ac:f5:da:d9:75:4c:e2:7b:2a:78:8f:6a:9f:f6:5b:04:96:42:9c:61:58:3a:1b:8f:a1:62:55:31:d1:7a:78:96:12:2c:7c:be:bb:74:ee:b1:c3:66:37:27:47:f9:20:c0:74:3d:d9:5a:5d:13:95:6f:a8:ae:ab:0f:f9:a9:17:cf:34:a2:21:86:0a:90:b6:a0:b6:a2:5b:59:a2:67:c1:ff:e9:92:5a:2f:3e:aa:54:7d:a5:11:4f:d1:ab:e3:fd:05:73:b5:c0:65:0d:f1:35:cc:f9:a0:cf:c6:6c:c7:56:f7:db:e2:c3:6d:dd:92:a2:7b:1e:ec:a5:d8:81:f2:ee:97:d2:4a:9f:e1:47:69:37:be:c4:82:68:53:02:eb:57:2c:df:18:cb:86:bc:24:aa:3f:44:2a:a4:64:f4:82:c6:a0:37:5c:ad:30:24:fd:3f:3c:bc:4d:43:f2:1c:13:32:5e:b2:bc:44:7d:70:39:c0:85:e8:28:de:1f:90:db";
        rsaKeyDto.d = "60:95:7c:0d:33:52:70:53:19:b1:fd:5e:3a:04:0a:c2:93:bb:bc:db:d6:b0:81:dd:c6:9c:df:10:44:37:67:86:84:7b:86:be:99:1b:22:73:52:7c:43:cf:60:65:0b:69:ac:7d:c7:c8:53:34:e9:f3:27:41:24:1e:fa:08:dc:ba:db:9c:ba:c8:d3:59:b6:c5:e6:0b:66:eb:0f:60:a9:e1:5d:05:4c:08:66:c8:8d:0a:37:c1:08:c9:3c:eb:5e:a8:59:31:34:c9:30:75:bf:1b:2e:61:43:4d:65:29:09:68:09:0f:f6:5c:eb:7a:03:26:ba:01:aa:5b:8f:4e:0d:76:53:2a:7c:eb:56:e8:df:f4:ec:d6:20:bb:33:3a:ea:d0:00:14:2e:82:5a:ad:0b:66:90:c6:e5:8e:7d:07:b9:1f:0a:d5:47:79:c7:6d:40:26:cb:a5:35:c9:ed:1f:62:4b:49:32:15:38:47:00:3e:a5:d0:3d:f5:8e:ae:4e:f7:18:c2:91:8d:a6:b5:63:c6:af:1d:ce:ea:64:4f:cd:8e:5d:a0:6a:f6:5c:39:b2:1f:ff:70:d2:9d:8a:06:dd:ba:5c:36:cc:b3:db:aa:8a:5e:da:31:90:ae:3e:63:70:d4:5b:9f:69:58:d2:59:42:83:56:b4:d2:05:84:34:f9:7c:11";
        rsaKeyDto.e = "65537";
        BigInteger privateExponent = new BigInteger(rsaKeyDto.d.replace(":",""),16);
        BigInteger modulus = new BigInteger(rsaKeyDto.n.replace(":",""),16);
        BigInteger e = new BigInteger(rsaKeyDto.e.replace(":",""),16);
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus,e);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(privateKeySpec);
        RSAPublicKey publicKey = (RSAPublicKey)factory.generatePublic(publicKeySpec);
        JWEObject jweObject = JWEObject.parse("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.cwP5TbZY-yxGroR4bwOwoM_7nqnoZWzmzLZixR3hkScp5oxFT5XQINdtz6lRmy0HcXopLQiJzd0CaHhjZAbJLVObw-pLVusDFcUDTPO1wdRkEnG7GQ6VvUSnVJjl481EYOBCdRqojulzn-Jcb7rHACNxoZlEwDiJnNggxmNmcfzHYXMpZYElrrbER5vf-ofksr36B4c0HJOC_yzUBKeXMeTKYS3BHq6mJlfzUncGruxfuQU_r8RCKLszkbiS7PYx0-x4k4I6YIAvThYvfFlhvBBWQ8AKy-iFWZlbXHCTZiR6w-gSZ9YoQp3e4_SxKh4ZYy8uIKD4bwW-7xc_eW6fKA.9v5VN3D2LDQMUFA0.RdlaBDvJSaEu1JuTuw7KPpCFrEizM0Y3o62DN0qOtqwZXe7Bx8RFkwUrRbACMPK1CjfJlIPRYWCcSpgbtPwY-rwbceY-VOMC8JK7Wqgp3Uawzef6u2FFrxLkCpai1bXtSdl0cpPdQdtKvDooK1ZUDdCLPz3p8Wu9aQ35N6kkelL7Puc9LiFHzXn8NA8keON-K1JuRJ3OcvZx0706JCSJyNvW59ggAWLCtErwy-JDC_8SlPMaAO1BRb455GB5vFU_YyynRCynh1uxp2vb7p_QhW1SNsfFPUqghfubnfCzyHa5KXXU7feZja9lpUxeKwjGVdwDELWqouS9ajn9Uj3tUm2rR5s7TdW6qvdGx0X4IIah4qFAbF9bCLKEIrhKtUVoDEY2QZgsvC2bri3RBsbR1WEv7qYgbFpUTUNu6UEDfqFGtTiMltwxqi0I7rJLiabL2N8o7KeMqbAJmyHmigPNurdi6Og0OOjceYJBSZvOH_x8yy9OoKE7ddyPOjsm4kv07NldeB1MdPygLORRc3_JTqHvB4MctoO2Nt3Vjcr6c_rgG-KIkjM_X89XHte_oySGTL5VfhnVlab0TxgqPlQvtRrYovAzjA-3yMx34W8NdT6siwsJXQ.ZrGCH3qrz8vucj-r7m9fbA");
        jweObject.decrypt(new RSADecrypter(privateKey));
        JSONObject json = jweObject.getPayload().toJSONObject();
        json.put("exp","2529876973");
        jweObject.encrypt(new RSAEncrypter(publicKey));


    }
}
