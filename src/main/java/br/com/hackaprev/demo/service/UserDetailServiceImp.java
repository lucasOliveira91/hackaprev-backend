package br.com.hackaprev.demo.service;

import br.com.hackaprev.demo.config.UserSS;
import br.com.hackaprev.demo.model.Usuario;
import br.com.hackaprev.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Optional;

@Service
@Primary
public class UserDetailServiceImp implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String cpf)   {
        Optional<Usuario> user = userRepository.findByCpf(cpf);
        return user.map(u -> new UserSS(
                u.getCpf(),
                u.getPassword(),
                u.getName()
        )).orElseThrow(() -> new UsernameNotFoundException(cpf));
    }
}