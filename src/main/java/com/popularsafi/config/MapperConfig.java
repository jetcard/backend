package com.popularsafi.config;

import com.popularsafi.dto.FondoDTO;
import com.popularsafi.dto.ReporteRiesgoDTO;
import com.popularsafi.model.Fondo;
import com.popularsafi.model.ReporteRiesgo;
import org.modelmapper.ModelMapper;

import org.modelmapper.TypeMap;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class MapperConfig {

    @Bean("fondoMapper")
    @Primary
    public ModelMapper fondoMapper() {
        ModelMapper mapper = new ModelMapper();

        //Escritura
        TypeMap<FondoDTO, Fondo> typeMap1 = mapper.createTypeMap(FondoDTO.class, Fondo.class);
        ///typeMap1.addMapping(FondoDTO::getC_FONDO_ID, (dest, v) -> dest.setC_FONDO_ID((String) v));
        ///typeMap1.addMapping(FondoDTO::getD_FONDO, (dest, v) -> dest.setD_FONDO((String) v));
        return mapper;
    }

    @Bean("RiesgoMapper")
    public ModelMapper RiesgoMapper() {
        ModelMapper mapper = new ModelMapper();

        //Escritura
        TypeMap<ReporteRiesgoDTO, ReporteRiesgo> typeMap1 = mapper.createTypeMap(ReporteRiesgoDTO.class, ReporteRiesgo.class);
        /*typeMap1.addMapping(ReporteRiesgoDTO::getCODIGOTCHN, (dest, v) -> dest.setCODIGOTCHN((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getCMONEDA, (dest, v) -> dest.setCMONEDA((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getNdocumento, (dest, v) -> dest.setNdocumento((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getTapaterno, (dest, v) -> dest.setTapaterno((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getTamaterno, (dest, v) -> dest.setTamaterno((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getTnombres, (dest, v) -> dest.setTnombres((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getDnacimiento, (dest, v) -> dest.setDnacimiento((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getTdireccion, (dest, v) -> dest.setTdireccion((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getCubigeo, (dest, v) -> dest.setCubigeo((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getDepartamento, (dest, v) -> dest.setDepartamento((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getProvincia, (dest, v) -> dest.setProvincia((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getDistrito, (dest, v) -> dest.setDistrito((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getCinmueble, (dest, v) -> dest.setCinmueble((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getActividad, (dest, v) -> dest.setActividad((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getSaldo_actual, (dest, v) -> dest.setSaldo_actual((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getCuotasatrasdas, (dest, v) -> dest.setCuotasatrasdas((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getEstado, (dest, v) -> dest.setEstado((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getCuota, (dest, v) -> dest.setCuota((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getSueldo, (dest, v) -> dest.setSueldo((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getFdesembolso, (dest, v) -> dest.setFdesembolso((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getTipooperacion, (dest, v) -> dest.setTipooperacion((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getS_INFOCORP, (dest, v) -> dest.setS_INFOCORP((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getNVALORIZACION, (dest, v) -> dest.setNVALORIZACION((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getV_EDIFICACION, (dest, v) -> dest.setV_EDIFICACION((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getV_PROPIEDAD, (dest, v) -> dest.setV_PROPIEDAD((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getV_COMERCIAL, (dest, v) -> dest.setV_COMERCIAL((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getV_REALIZACIONSOL, (dest, v) -> dest.setV_REALIZACIONSOL((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getV_REALIZACIONDOL, (dest, v) -> dest.setV_REALIZACIONDOL((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getF_VALORIZACION, (dest, v) -> dest.setF_VALORIZACION((String) v));
        typeMap1.addMapping(ReporteRiesgoDTO::getNcuotas_generadas, (dest, v) -> dest.setNcuotas_generadas((String) v));*/
        return mapper;
    }
}
