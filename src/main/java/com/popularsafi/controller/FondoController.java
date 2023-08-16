package com.popularsafi.controller;

import com.popularsafi.dto.FondoDTO;
import com.popularsafi.model.Fondo;
import com.popularsafi.service.IFondoServ;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/fondo")
public class FondoController {

    private final IFondoServ serv;

    private final ModelMapper modelMapper;

    public FondoController(IFondoServ serv, ModelMapper modelMapper) {
        this.serv = serv;
        this.modelMapper = modelMapper;
    }

    @GetMapping
    public ResponseEntity<List<FondoDTO>> obtenerFondo() {
        List<FondoDTO> lstfondo  = serv.findAll().stream().map(this::convertToDto).collect(Collectors.toList());
        return new ResponseEntity<>(lstfondo,HttpStatus.OK);
    }
/*
    @GetMapping
    @ResponseBody
    public List<FondoDTO> getPosts() {
        //...
        List<Fondo> posts = serv.findAll();
        return posts.stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }*/
/*
    public static void main(String[] args) {
        //List<FondoDTO> lstfondo  = serv.findAll().stream().map(new FondoController()::convertToDto0).collect(Collectors.toList());
        //lstfondo.forEach(System.out::println);
        System.out.println("---------------------");

        ModelMapper modelMapper = new ModelMapper();

        // Crear un objeto DTO
        FondoDTO dto = new FondoDTO();
        dto.setC_FONDO_ID("John");
        dto.setD_FONDO("30");

        // Mapear el DTO a una entidad Employee
        Fondo employee = modelMapper.map(dto, Fondo.class);

        System.out.println(employee.getC_FONDO_ID()); // Imprime "John"
        System.out.println(employee.getD_FONDO());  // Imprime 30
    }
*/
    private FondoDTO convertToDto(Fondo obj){
        return modelMapper.map(obj, FondoDTO.class);
    }

    private Fondo convertToEntity(FondoDTO dto){
        return modelMapper.map(dto, Fondo.class);
    }
}
