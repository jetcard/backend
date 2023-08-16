package com.popularsafi.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

@Getter
@Setter
@Data
@NoArgsConstructor
@Entity
@Table(name = "FONDO")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@AllArgsConstructor
public class Fondo {
    @Id
    @Column(nullable = false, length = 4, unique = true)
    private String C_FONDO_ID;

    @Column(nullable = false, length = 200)
    private String D_FONDO;

    public String getC_FONDO_ID() {
        return C_FONDO_ID;
    }

    public String getD_FONDO() {
        return D_FONDO;
    }
}
