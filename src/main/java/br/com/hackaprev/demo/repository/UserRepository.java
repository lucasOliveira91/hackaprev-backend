package br.com.hackaprev.demo.repository;

import br.com.hackaprev.demo.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Usuario, Integer> {

     Optional<Usuario> findByCpf(String cpf);

}
