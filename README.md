# SecurityJwt

https://www.youtube.com/watch?v=X80nJ5T7YpE


##### SecurityConfiguration (수정중)
```JAVA
package kr.co.dfcc.dsrm.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import kr.co.dfcc.dsrm.service.SecurityService;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	SecurityService userDetailsService;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {		// Spring Security 에서 모든 인증은 AuthenticationManager를 통해 이루어지며 AuthenticationManager를 생성하기 위해서는
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder()); // AuthenticationManagerBuilder를 사용한다.
	}																					// 로그인 처리 즉, 인증을 위해서는 UserDetailService를 통해서 필요한 정보들을 가져오는데, 예제에서는 서비스클래스에서 이를 처리한다.


	@Override
	public void configure(WebSecurity web) throws Exception { // static 디렉터리의 하위 파일 목록은 인증 무시
		web.ignoring().antMatchers("/static/**");
	}


	@Override
	protected void configure(HttpSecurity http) throws Exception { // Http 요청에 대한 웹 기반 보안을 구성
		http.formLogin().loginProcessingUrl("/index");
		
		http.csrf().disable()
			.cors().disable()
				.authorizeRequests()
				.antMatchers("/api/**").permitAll()
				.antMatchers("/swagger-ui.html").permitAll()
				.antMatchers("/index").permitAll()
//			.and()
//				.formLogin()										// 기본 제공되는 loginForm을 사용하지 않을 경우 사용
//				.loginPage("../views/Login.vue") // vue 로그인 페이지	// 커스텀 로그인 페이지 경로 지정
//				.defaultSuccessUrl("../views/Main.vue")				// 로그인이 성공했을 경우 이동 페이지
//				.permitAll()
//			.and()
//				.logout()
//				.logoutSuccessUrl("../views/Login.vue")
//				.invalidateHttpSession(true)						// Http 세션을 초기화
//			.and()
//				.exceptionHandling()
				;
		
		//http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
	}

//	@Override
//	@Bean
//	public AuthenticationManager authenticationManagerBean() throws Exception {
//		return super.authenticationManagerBean();
//	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
}

```

##### UserDetailsService (수정중)
```JAVA
package kr.co.dfcc.dsrm.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import kr.co.dfcc.dsrm.domain.AdminDTO;
import kr.co.dfcc.dsrm.domain.Role;

@Service
public class SecurityService implements UserDetailsService {
	
	@Autowired
	AdminService adminService;
	
	@Transactional
	public String joinAdmin(AdminDTO admin) {
		// 비밀번호 암호화
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		admin.setPassword(passwordEncoder.encode(admin.getPassword()));
		
		int result = adminService.insertAdmin(admin);
		
		String adminId = null;
		if(result > 0) {
			adminId = admin.getAdminId();
		}
		
		return adminId;
	}
	
	@Override
	public UserDetails loadUserByUsername(String adminId) throws UsernameNotFoundException {	
		Optional<AdminDTO> optional = adminService.findById(adminId);			// adminId를 통한 AdminDTO 반환
		AdminDTO admin = optional.get();										// AdminDTO 타입으로 반환
		
		List<GrantedAuthority> authorities = new ArrayList<>();					// ROLE를 설정할 리스트
		
		authorities.add(new SimpleGrantedAuthority(Role.ADMIN.getValue()));				// 임의로 ROLE_ADMIN 주입
		
		return new User(admin.getAdminId(), admin.getPassword(), authorities);	// UserDetails를 구현한 User반환
	}
}
```

개발 프로젝트 Security, Jwt 진행중.. 성공적으로 완료 시 수정할 듯.

### 토큰 사용예제

##### SecurityController
```JAVA
package kr.co.dfcc.dsrm.configuration.security;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/security")
public class SecurityController {
	
	@Autowired
	private SecurityService securityService;
	
	@GetMapping("/create/token") // 실제 운영에선 post방식으로 하며 매개변수는 DTO로 받아서 아이디 비밀번호 처리
	public Map<String, Object> createToken(@RequestParam(value = "subject")String subject) {
		String token = securityService.createToken(subject, (2* 1000 *60 )); // 2 분 설정
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		map.put("result", token);
		return map;
	}
	
	@GetMapping("/get/subject")
	public Map<String, Object> getSubject(@RequestParam(value = "token") String token) {
		String subject = securityService.getSubject(token);
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		map.put("result", subject);
		return map;
	}
}
```

##### SecurityService
```JAVA
package kr.co.dfcc.dsrm.configuration.security;

import java.security.Key;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class SecurityService {
	private static final String SECRET_KEY = "sdfhkjasdjfnkdjksznfkdjszdfszjnkfkszdj"; // 임으로 만든값 저렇게하면 안됨
	
	
	// 로그인 서비스 던질 때 같이 사용
	public String createToken(String subject, long expTime) { // expTime : 만료시간
		if(expTime <= 0) {
			throw new RuntimeException("만료시간이 0보다 커야함");
		}
		
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256; // 서명 알고리즘
		
		byte[] secretKeyBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY); // 시크릿 키 바이트로 변환
		Key signingKey = new SecretKeySpec(secretKeyBytes, signatureAlgorithm.getJcaName()); 
		
		return Jwts.builder()		// Jwts builder pattern
				.setSubject(subject) // subject : userId
				.signWith(signatureAlgorithm, secretKeyBytes)
				.setExpiration(new Date(System.currentTimeMillis() + expTime)) // 만료시간 설정
				.compact();
	}
	
	// 토큰 검증하는 메서드임 (원래는 boolean타입으로)
	public String getSubject(String token) {
		//claims : payload에 담긴 정보
		Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY)) // 암호화 시킴
				.parseClaimsJws(token) // 생성했던 토큰 정보를 풀어줌
				.getBody();
		
		return claims.getSubject();
	}
}
```




