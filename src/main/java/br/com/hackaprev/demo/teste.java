package br.com.hackaprev.demo;

import br.com.hackaprev.demo.config.Sha1PasswordEncoder;

import java.security.NoSuchAlgorithmException;

public class teste {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.println(new Sha1PasswordEncoder().encode("123"));
    }
}
