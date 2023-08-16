package com.popularsafi.service.impl;

import com.popularsafi.model.Fondo;
import com.popularsafi.repo.IFondoRepo;
import com.popularsafi.repo.IGenericRepo;
import com.popularsafi.service.IFondoServ;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
//@RequiredArgsConstructor
public class FondoImpl extends CRUDImpl<Fondo, String> implements IFondoServ {

    private final IFondoRepo repo;
    @Autowired
    public FondoImpl(IFondoRepo repo) {
        this.repo = repo;
    }
    @Override
    protected IGenericRepo<Fondo, String> getRepo() {
        return repo;
    }

    public List<Fondo> findAll() {
        return repo.findAll();
    }
}