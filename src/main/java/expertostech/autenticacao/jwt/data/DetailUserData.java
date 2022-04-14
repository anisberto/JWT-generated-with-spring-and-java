package expertostech.autenticacao.jwt.data;

import expertostech.autenticacao.jwt.model.UsuarioModel;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class DetailUserData implements UserDetails {

    private final Optional<UsuarioModel> usuarioModel;

    public DetailUserData(Optional<UsuarioModel> usuarioModel) {
        this.usuarioModel = usuarioModel;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return new ArrayList<>();
    }

    @Override
    public String getPassword() {
        return usuarioModel.orElse(new UsuarioModel()).getPassword();
    }

    @Override
    public String getUsername() {
        return usuarioModel.orElse(new UsuarioModel()).getLogin();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
