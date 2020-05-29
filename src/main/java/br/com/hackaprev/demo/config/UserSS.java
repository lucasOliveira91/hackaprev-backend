package br.com.hackaprev.demo.config;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.context.annotation.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

@NoArgsConstructor
@Getter
public class UserSS implements UserDetails {

    private String id;
    private String nome;
    private String matricula;
    private String cpf;
    private String password;
    private Collection<? extends GrantedAuthority> authorities = new ArrayList<>();

    public UserSS(String cpf, String password, String nome) {
        this.nome = nome;
        this.cpf = cpf;
        this.password = password;
    }

    public String getId() {
        return id;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return cpf;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    //is user active?
    @Override
    public boolean isEnabled() {
        return true;
    }

    public boolean hasRole(Role role) {
        return getAuthorities().contains(new SimpleGrantedAuthority(""));
    }
}