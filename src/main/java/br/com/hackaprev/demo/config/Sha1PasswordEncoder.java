package br.com.hackaprev.demo.config;

import org.springframework.security.crypto.password.PasswordEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha1PasswordEncoder implements PasswordEncoder {
    private MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    private  MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

    public Sha1PasswordEncoder() throws NoSuchAlgorithmException {
    }

    @Override
    public String encode(CharSequence texto) {
        String senhaCriptografada = null;
        if (sha1 != null) {
            byte[] arraySenhaCriptografada = sha1.digest(texto.toString().getBytes());
            senhaCriptografada = new String(hexCodes(arraySenhaCriptografada));
        }
        return senhaCriptografada;

    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encode(rawPassword).equals(encodedPassword);
    }


    private static char[] hexCodes(byte[] texto) {
        char[] hexOutput = new char[texto.length * 2];
        String hexString;
        for (int i = 0; i < texto.length; i++) {
            hexString = "00" + Integer.toHexString(texto[i]);
            hexString.toUpperCase().getChars(hexString.length() - 2, hexString.length(), hexOutput, i * 2);
        }
        return hexOutput;
    }

}
