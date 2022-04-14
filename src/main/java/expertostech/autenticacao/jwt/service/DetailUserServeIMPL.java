package expertostech.autenticacao.jwt.service;

import expertostech.autenticacao.jwt.data.DetailUserData;
import expertostech.autenticacao.jwt.model.UsuarioModel;
import expertostech.autenticacao.jwt.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class DetailUserServeIMPL implements UserDetailsService {
    @Autowired
    private UsuarioRepository usuarioRepository;

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        Optional<UsuarioModel> usuario = usuarioRepository.findByLogin(login);
        if(usuario.isEmpty()){
            throw new UsernameNotFoundException("Usuario não encontrado");
        }
        return new DetailUserData(usuario);
    }
}
