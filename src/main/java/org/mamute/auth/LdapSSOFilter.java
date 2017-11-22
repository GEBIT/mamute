package org.mamute.auth;

import javax.enterprise.event.Observes;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.mamute.dao.UserDAO;
import org.mamute.model.LoggedUser;
import org.mamute.model.User;

import br.com.caelum.vraptor.environment.Environment;
import br.com.caelum.vraptor.events.MethodReady;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Enumeration;

public class LdapSSOFilter {

	private static final Logger LOG = LoggerFactory.getLogger(LdapSSOFilter.class);

	@Inject private Environment env;
	@Inject private UserDAO users;
	@Inject private LDAPApi ldap;
	@Inject private LoggedUser loggedUser;
	@Inject private HttpServletRequest request;
	@Inject private Access system;

	public void checkSSO(@Observes MethodReady methodReady) {
		if (env.supports(LDAPApi.LDAP_SSO) && !loggedUser.isLoggedIn() && request.getRequestURI() != null
				&& !request.getRequestURI().endsWith("/logout")) {
			String userName = getRemoteUser();
			if (LOG.isDebugEnabled()) {
				LOG.debug("SSO: username: " + userName);
				Enumeration<String> headers = request.getHeaderNames();
				LOG.debug("SSO: headers: " + Collections.list(request.getHeaderNames()));
			}

			if (userName != null && ldap.authenticateSSO(userName)) {
				String email = ldap.getEmail(userName);
				User retrieved = users.findByEmail(email);

				if (retrieved != null) {
					system.login(retrieved);
				}
			}
		}
	}

	private String getRemoteUser() {
		String remoteUser = request.getRemoteUser();
		if (remoteUser == null) {
			String headerName = env.get(ldap.LDAP_SSO_REMOTE_USER_ATTRIBUTE);
			if (headerName != null && !"".equals(headerName)) {
				remoteUser = request.getHeader(headerName);
			}
		}
		return remoteUser;
	}

}
