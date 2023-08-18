package com.popularsafi.dto;

//import jakarta.validation.constraints.NotNull;
import lombok.*;

@Getter
@Setter
@Data
@AllArgsConstructor
//@NoArgsConstructor
public class FondoDTO {
    //@NotNull
    private String C_FONDO_ID;
    //@NotNull
    private String D_FONDO;

    public void setC_FONDO_ID(String c_FONDO_ID) {
        C_FONDO_ID = c_FONDO_ID;
    }

    public void setD_FONDO(String d_FONDO) {
        D_FONDO = d_FONDO;
    }
}
