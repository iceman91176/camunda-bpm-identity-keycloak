package org.camunda.bpm.extension.keycloak.showcase.sso;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.StringUtils;

/**
 * @author Rob Winch
 * @author Josh Cummings
 * @since 5.1
 */
public class KeycloakAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
	private String authorityPrefix = "SCOPE_";

	private Collection<String> attributeNames =
			Arrays.asList("scope", "scp");


	public final AbstractAuthenticationToken convert(Jwt jwt) {
		Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
		return new JwtAuthenticationToken(jwt, authorities);
    }

    public void setAuthorityPrefix(String authorityPrefix){
        this.authorityPrefix = authorityPrefix;
    }

    public void setAuthorityAttributeNames(Collection<String> attributeNames){
        this.attributeNames = attributeNames;
    }

	protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
		return this.getScopes(jwt)
						.stream()
						.map(authority -> authorityPrefix + authority)
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList());
	}

	private Collection<String> getScopes(Jwt jwt) {
		for ( String attributeName : this.attributeNames ) {
			Object scopes = jwt.getClaims().get(attributeName);
			if (scopes instanceof String) {
				if (StringUtils.hasText((String) scopes)) {
					return Arrays.asList(((String) scopes).split(" "));
				} else {
					return Collections.emptyList();
				}
			} else if (scopes instanceof Collection) {
				return (Collection<String>) scopes;
			}
		}

		return Collections.emptyList();
	}
}