package expertostech.autenticacao.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import expertostech.autenticacao.jwt.data.DetailUserData;
import expertostech.autenticacao.jwt.model.UsuarioModel;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

public class JWTAutenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static final int TOKEN_EXPIRATION = 6000_0;

    public static final String TOKEN_PASSWORD = "b40a4911-deff-4a7a-b325-a5af8d423f0d";
    private final AuthenticationManager authenticationManager;

    public JWTAutenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            UsuarioModel usuarioModel = new ObjectMapper()
                    .readValue(request.getInputStream(), UsuarioModel.class);
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    usuarioModel.getLogin(), usuarioModel.getPassword(), new ArrayList<>()
            ));
        } catch (IOException e) {
            throw new RuntimeException("Erro ao autenticar usuario");
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        try {
            DetailUserData userData = (DetailUserData) authResult.getPrincipal();
            String token = JWT.create().
                    withSubject(userData.getUsername())
                    .withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_EXPIRATION))
                    .sign(Algorithm.HMAC512(TOKEN_PASSWORD));
            response.getWriter().write(token);
            response.getWriter().flush();
        }catch (Exception error){
            error.printStackTrace();
        }
    }
}
