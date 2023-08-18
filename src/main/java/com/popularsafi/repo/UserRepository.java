package com.popularsafi.repo;

import java.util.Optional;

import com.popularsafi.model.User;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends IGenericRepo<User, Integer> {
    Optional<User> findByEmail(String email);
}