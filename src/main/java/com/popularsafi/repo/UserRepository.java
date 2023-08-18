package com.popularsafi.repo;

import java.util.Optional;

import com.popularsafi.model.User;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends IGenericRepo<User, Integer> {
    /*Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);*/
    // Since email is unique, we'll find users by email
    Optional<User> findByEmail(String email);
}