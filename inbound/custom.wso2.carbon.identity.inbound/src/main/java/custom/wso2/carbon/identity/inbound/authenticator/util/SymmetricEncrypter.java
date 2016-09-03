package custom.wso2.carbon.identity.inbound.authenticator.util;

import custom.wso2.carbon.identity.inbound.authenticator.SymcorInboundConstants;
import org.wso2.carbon.core.util.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class SymmetricEncrypter {

    private static final String ENCRYPTION_ALGO = "AES";

    public static byte[] encryptWithSymmetricKey(byte[] plainText) throws CryptoException {
        Cipher c = null;
        byte[] encryptedData = null;

        try {
            c = Cipher.getInstance(ENCRYPTION_ALGO);
            c.init(Cipher.ENCRYPT_MODE, getSymmetricKey());
            encryptedData = c.doFinal(plainText);
        } catch (Exception e) {
            throw new CryptoException("Error when encrypting data.", e);
        }
        return encryptedData;
    }

    public static SecretKey getSymmetricKey() throws CryptoException {
        FileInputStream fileInputStream = null;
        Properties properties;
        SecretKey symmetricKey;
        String propertyKey = "symmetric.key";

        File file = new File(SymcorInboundConstants.SYMMETRIC_KEY_FILE_PATH);
        if (file.exists()) {
            try {
                fileInputStream = new FileInputStream(file);
                properties = new Properties();
                properties.load(fileInputStream);
                symmetricKey = new SecretKeySpec(properties.getProperty(propertyKey).getBytes(), 0,
                        32, ENCRYPTION_ALGO); //byte size 32 is to make 256bit
                return symmetricKey;
            } catch (FileNotFoundException e) {
                throw new CryptoException("File not found in path :" + SymcorInboundConstants.SYMMETRIC_KEY_FILE_PATH);
            } catch (IOException e) {
                throw new CryptoException("Error while loading properties from file");
            }
        }
        return null;
    }
}
