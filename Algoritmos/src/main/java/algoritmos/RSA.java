package algoritmos;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import java.util.Base64;

public class RSA {

    private String publicKey;//Clave publica
    private String privateKey;//clave privado.

    // <editor-fold defaultstate="collapsed" desc="Getters & Setters">
    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    // </editor-fold>
    public RSA() throws Exception {
        KeyPair kp = this.generateKeyPair();

        this.publicKey = this.keyToBase64String(kp.getPublic());
        this.privateKey = this.keyToBase64String(kp.getPrivate());

    }

    /**
     * Encriptar se usa la clave publica y Desencriptar se usa la clave privada
     *
     * @param key
     * @param keyType, public or private
     */
    public RSA(String key, String keyType) throws Exception {
        if ("public".equals(keyType)) {
            this.publicKey = key;
        } else if ("private".equals(keyType)) {
            this.privateKey = key;
        } else {
            throw new Exception("No existe el keyType: " + keyType);
        }
    }

    // Convertir una clave a Base64
    private String keyToBase64String(java.security.Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Convertir una clave de Base64 a un objeto clave
    private java.security.Key base64StringToKey(String base64String, String keyType) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64String);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
        if (keyType.equals("public")) {
            return keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(keyBytes));
        } else if (keyType.equals("private")) {
            return keyFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(keyBytes));
        } else {
            throw new IllegalArgumentException("Invalid key type");
        }
    }

    // Método para generar un par de claves (pública y privada)
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(2048, random);
        return keyGen.generateKeyPair();
    }

    // Método para cifrar un mensaje con la clave pública
    public String encrypt(String plainText, String publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, (PublicKey) this.base64StringToKey(publicKey, "public"));
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Método para descifrar un mensaje con la clave privada
    public String decrypt(String encryptedText, String privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, (PrivateKey) this.base64StringToKey(privateKey, "private"));
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    /**
     * Pruba sin la interfaz
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            // Generar el par de claves
            RSA rsa = new RSA();

            // Mensaje a cifrar
            String originalMessage = "Este es un mensaje secreto";
            System.out.println("Mensaje original: " + originalMessage);

            // Cifrar el mensaje
            String encryptedMessage = rsa.encrypt(originalMessage, rsa.getPublicKey());
            System.out.println("Mensaje cifrado: " + encryptedMessage);

            // Descifrar el mensaje
            String decryptedMessage = rsa.decrypt(encryptedMessage, rsa.getPrivateKey());
            System.out.println("Mensaje descifrado: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
