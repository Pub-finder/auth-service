package com.pubfinder.auth_service.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pubfinder.auth_service.dto.AuthenticationResponse;
import com.pubfinder.auth_service.dto.LoginRequest;
import com.pubfinder.auth_service.dto.TokenValidationResponse;
import com.pubfinder.auth_service.models.Token;
import com.pubfinder.auth_service.models.User;
import com.pubfinder.auth_service.service.AuthService;
import com.pubfinder.auth_service.util.TestUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
public class AuthControllerTest {

    @MockBean
    private AuthService authService;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    public void validateTokenTest() throws Exception {
        when(authService.validateToken(any())).thenReturn(TokenValidationResponse.VALID);
        Token token = TestUtil.generateMockToken(user);

        mockMvc.perform(get("/auth/validateToken/{token}", token.getToken())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    public void refreshTokenTest() throws Exception {
        Token access = TestUtil.generateMockToken(user);
        Token refresh = TestUtil.generateMockToken(user);
        AuthenticationResponse authenticationResponse = TestUtil.generateMockAuthenticationResponse(access.getToken(), refresh.getToken());

        when(authService.refreshToken(any())).thenReturn(authenticationResponse);

        mockMvc.perform(get("/auth/refreshToken/{token}", refresh.getToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authenticationResponse)))
                .andExpect(status().isOk());
    }

    @Test
    public void loginTest() throws Exception {
        Token access = TestUtil.generateMockToken(user);
        Token refresh = TestUtil.generateMockToken(user);
        AuthenticationResponse authenticationResponse = TestUtil.generateMockAuthenticationResponse(access.getToken(), refresh.getToken());

        LoginRequest loginRequest = LoginRequest.builder()
                .username("username")
                .password("password")
                .build();

        when(authService.login(loginRequest)).thenReturn(authenticationResponse);

        mockMvc.perform(post("/auth/login", loginRequest)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authenticationResponse)))
                .andExpect(status().isOk());
    }

    @Test
    public void logoutTest() throws Exception {
        Token access = TestUtil.generateMockToken(user);
        doNothing().when(authService).logout(access.getToken());

        mockMvc.perform(delete("/auth/logout/{token}", access)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNoContent());
    }

    @Test
    public void generateTokenTest() throws Exception {
        Token access = TestUtil.generateMockToken(user);
        Token refresh = TestUtil.generateMockToken(user);
        AuthenticationResponse authenticationResponse = TestUtil.generateMockAuthenticationResponse(access.getToken(), refresh.getToken());
        when(authService.generateToken(user.getId())).thenReturn(authenticationResponse);

        mockMvc.perform(get("/auth/generateToken/{userId}", user.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authenticationResponse)))
                .andExpect(status().isCreated());
    }


    User user = TestUtil.generateMockUser();
}
