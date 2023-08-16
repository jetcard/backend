package com.popularsafi.repo;

import com.popularsafi.model.ReporteRiesgo;

import java.util.Date;
import java.util.List;

public interface IRepoRiesgo  {
    List<ReporteRiesgo> obtenerReporteRiesgo(String fondo, Date fecha);
}
