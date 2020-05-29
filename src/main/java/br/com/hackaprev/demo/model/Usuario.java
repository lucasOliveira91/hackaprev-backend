package br.com.hackaprev.demo.model;

import lombok.Data;

import javax.persistence.*;
import java.math.BigDecimal;
import java.time.LocalDate;

@Entity
@Data
public class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String name;
    private Character gender;
    private LocalDate birthdate;
    private BigDecimal income;
    private String cpf;
    private String password;
}
