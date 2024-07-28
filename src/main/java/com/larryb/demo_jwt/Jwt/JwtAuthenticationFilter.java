package com.larryb.demo_jwt.Jwt;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, 
                                    @NonNull HttpServletResponse response, 
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        
        try {
            // Obtén el token del request
            final String token = getTokenFromRequest(request);
            final String username;

            if (token == null) {
                log.warn("Token no encontrado en el request");
                filterChain.doFilter(request, response);
                return;
            }

            // Extrae el nombre de usuario del token
            username = jwtService.getUsernameFromToken(token);
            log.info("Token obtenido: {}", token);
            log.info("Username obtenido del token: {}", username);

            // Verifica si el nombre de usuario no es null y no hay autenticación en el contexto de seguridad
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                log.info("UserDetails cargado: {}", userDetails);

                // Verifica si el token es válido
                if (jwtService.isTokenValid(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Establece la autenticación en el contexto de seguridad
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.info("Autenticación configurada correctamente para el usuario: {}", username);
                } else {
                    log.warn("Token inválido para el usuario: {}", username);
                }
            } else {
                log.warn("Username es null o ya existe una autenticación en el contexto");
            }
        } catch (Exception e) {
            log.error("Error en doFilterInternal: ", e);
            // Puedes manejar la excepción aquí o lanzarla nuevamente
            throw new ServletException("Error en el filtro de autenticación JWT", e);
        }

        // Continúa con el siguiente filtro
        filterChain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        // Obtén el header de autorización
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Verifica si el header no es vacío y empieza con "Bearer "
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            log.info("Auth header encontrado: {}", authHeader);
            return authHeader.substring(7);
        }
        log.warn("Auth header no encontrado o no empieza con 'Bearer '");
        return null;
    }
}
