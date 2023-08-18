package com.popularsafi.service;

import com.popularsafi.payload.request.SignUpRequest;
import com.popularsafi.payload.request.SigninRequest;
import com.popularsafi.payload.response.JwtAuthenticationResponse;
public interface AuthenticationService {
    JwtAuthenticationResponse signup(SignUpRequest request);

    JwtAuthenticationResponse signin(SigninRequest request);
}
