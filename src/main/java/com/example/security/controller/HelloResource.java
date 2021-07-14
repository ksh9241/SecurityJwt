package com.example.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.security.models.AuthenticationRequest;
import com.example.security.models.AuthenticationResponse;
import com.example.security.service.myUserDetailsService;
import com.example.security.util.JwtUtil;

@RestController
public class HelloResource {
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	myUserDetailsService userDetailsService;
	
	@Autowired
	JwtUtil jwtTokenUtil;
	
	@RequestMapping({"/hello"})
	public String hello() {
		return "hello World";
	}
	
	@PostMapping(value = "/authenticate")
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationReqeust) throws Exception {
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(authenticationReqeust.getUsername(), authenticationReqeust.getPassword())	
			);
			
		} catch (BadCredentialsException e) {
			throw new Exception("incorrect username or password", e);
		} 
		
		final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationReqeust.getUsername());
		final String jwt = jwtTokenUtil.generateToken(userDetails);
		
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}
}
