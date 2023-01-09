package org.conjur.jenkins.api;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import org.conjur.jenkins.configuration.ConjurConfiguration;
import org.conjur.jenkins.configuration.ConjurJITJobProperty;
import org.conjur.jenkins.configuration.FolderConjurConfiguration;
import org.conjur.jenkins.configuration.GlobalConjurConfiguration;
import org.conjur.jenkins.jwtauth.impl.JwtToken;

import hudson.model.AbstractItem;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.model.Run;
import hudson.security.ACL;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class ConjurAPI {

	public static class ConjurAuthnInfo {
		public String applianceUrl;
		public String authnPath;
		public String account;
		public String login;
		public String apiKey;
	}

	private static final Logger LOGGER = Logger.getLogger(ConjurAPI.class.getName());

	static Logger getLogger() {
		return Logger.getLogger(ConjurAPI.class.getName());
	}

	private static void defaultToEnvironment(ConjurAuthnInfo conjurAuthn) {
		LOGGER.log(Level.FINE, "Start of defaultToEnvironment");
		Map<String, String> env = System.getenv();
		LOGGER.log(Level.FINE, "Start of defaultToEnvironment"+System.getenv("CONJUR_AUTHN_API_KEY"));
		if (conjurAuthn.applianceUrl == null && env.containsKey("CONJUR_APPLIANCE_URL"))
			conjurAuthn.applianceUrl = env.get("CONJUR_APPLIANCE_URL");
		if (conjurAuthn.account == null && env.containsKey("CONJUR_ACCOUNT"))
			conjurAuthn.account = env.get("CONJUR_ACCOUNT");
		if (conjurAuthn.login == null && env.containsKey("CONJUR_AUTHN_LOGIN"))
			conjurAuthn.login = env.get("CONJUR_AUTHN_LOGIN");
		if (conjurAuthn.apiKey == null && env.containsKey("CONJUR_AUTHN_API_KEY"))
			conjurAuthn.apiKey = env.get("CONJUR_AUTHN_API_KEY");
		LOGGER.log(Level.FINE, "End of defaultToEnvironment");
	}

	@SuppressFBWarnings
	public static String getAuthorizationToken(OkHttpClient client, ConjurConfiguration configuration,
			ModelObject context) throws IOException {
		LOGGER.log(Level.FINE, "Start of  getAuthorizationToken()");
		String resultingToken = null;

		List<UsernamePasswordCredentials> availableCredentials = null;

		availableCredentials = CredentialsProvider.lookupCredentials(UsernamePasswordCredentials.class, Jenkins.get(),
				ACL.SYSTEM, Collections.<DomainRequirement>emptyList());
		LOGGER.log(Level.FINE, "Available credentials inside getAuthorization token" + availableCredentials.toString());

		if (context != null) {
			LOGGER.log(Level.FINE, "Context not null >>Available Credential"+ availableCredentials.toString()+"Context"+context.getClass());
		
			if (context instanceof Run) {
				LOGGER.log(Level.FINE,
					"Context instance of Run " + availableCredentials.toString());

				availableCredentials.addAll(CredentialsProvider.lookupCredentials(UsernamePasswordCredentials.class,
						((Run) context).getParent(), ACL.SYSTEM, Collections.<DomainRequirement>emptyList()));
			} else {
				
				if ((context instanceof AbstractItem)) {
					LOGGER.log(Level.FINE,
							"Context instance of AbstractItem getAuthorization token" + availableCredentials.toString());

					availableCredentials.addAll(CredentialsProvider.lookupCredentials(UsernamePasswordCredentials.class,
							(AbstractItem) context, ACL.SYSTEM, Collections.<DomainRequirement>emptyList()));
				}
				else
				{
					LOGGER.log(Level.FINE,"Jenkins.get()"+Jenkins.get().getDisplayName());
					
					context = Jenkins.get();
					
				}

			}
		
		}
		
	
		LOGGER.log(Level.FINE,"Calling getConjurAuthnInfo()");
		ConjurAuthnInfo conjurAuthn = getConjurAuthnInfo(configuration, availableCredentials, context);
		LOGGER.log(Level.FINE,"End getConjurAuthnInfo()");
		
		Request request = null;
		if (conjurAuthn.login != null && conjurAuthn.apiKey != null) {
			LOGGER.log(Level.FINE, "Authenticating with Conjur (authn)");
			request = new Request.Builder()
					.url(String.format("%s/%s/%s/%s/authenticate", conjurAuthn.applianceUrl, conjurAuthn.authnPath,
							conjurAuthn.account, URLEncoder.encode(conjurAuthn.login, "utf-8")))
					.post(RequestBody.create(MediaType.parse("text/plain"), conjurAuthn.apiKey)).build();
		} else if (conjurAuthn.authnPath != null && conjurAuthn.apiKey != null) {
			String authnPath = conjurAuthn.authnPath.indexOf("/") == -1 ? "authn-jwt/" + conjurAuthn.authnPath
					: conjurAuthn.authnPath;
			LOGGER.log(Level.FINE, "Authenticating with Conjur (JWT) authnPath={0}", authnPath);
			String authnAPIKey = conjurAuthn.apiKey;
			String apikey = String.join("", authnAPIKey.split("jwt="));
			
			LOGGER.log(Level.FINE, "Authenticating with Conjur APIKey="+apikey);
			request = new Request.Builder()
					.url(String.format("%s/%s/%s/authenticate", conjurAuthn.applianceUrl, authnPath,
							conjurAuthn.account))
					.post(RequestBody.create(MediaType.parse("text/plain"), conjurAuthn.apiKey)).build();

		}

		if (request != null) {
			Response response = client.newCall(request).execute();
			resultingToken = Base64.getEncoder().withoutPadding()
					.encodeToString(response.body().string().getBytes("UTF-8"));
			LOGGER.log(Level.FINEST,
					() -> "Conjur Authenticate response " + response.code() + " - " + response.message());
			if (response.code() != 200) {
				throw new IOException("Error authenticating to Conjur [" + response.code() + " - " + response.message()
						+ "\n" + resultingToken);
			}
		} else {
			LOGGER.log(Level.FINE, "Failed to find credentials for conjur authentication");
		}
		LOGGER.log(Level.FINE, "End of  getAuthorizationToken()");
		return resultingToken;
	}

	public static ConjurAuthnInfo getConjurAuthnInfo(ConjurConfiguration configuration,
			List<UsernamePasswordCredentials> availableCredentials, ModelObject context) {
		LOGGER.log(Level.FINE, "Start getConjurAuthnInfo()" +context);
		ConjurAuthnInfo conjurAuthn = new ConjurAuthnInfo();

		if (configuration != null) {
			LOGGER.log(Level.FINE, "Configuration not null" +configuration);

			if (availableCredentials != null) {
				initializeWithCredential(conjurAuthn, configuration.getCredentialID(), availableCredentials);
			}

			String applianceUrl = configuration.getApplianceURL();
			if (applianceUrl != null && !applianceUrl.isEmpty()) {
				conjurAuthn.applianceUrl = applianceUrl;
			}
			String account = configuration.getAccount();
			if (account != null && !account.isEmpty()) {
				LOGGER.log(Level.FINE, "account inside getConjurAuthnInfo>>"+account);
				conjurAuthn.account = account;
			}
			// Default authentication will be authn
			conjurAuthn.authnPath = "authn";
		}

		// Default to Environment variables if not values present
		defaultToEnvironment(conjurAuthn);

		// Check for Just-In-time Credential Access if no login and apikey
		if (conjurAuthn.login == null && conjurAuthn.apiKey == null && context != null) {
			LOGGER.log(Level.FINE, "calling setConjurAuthnForJITCredentialAccess>>");
			setConjurAuthnForJITCredentialAccess(context, conjurAuthn);
		}
		LOGGER.log(Level.FINE, "End getConjurAuthnInfo()");
		return conjurAuthn;
	}

	private static void setConjurAuthnForJITCredentialAccess(ModelObject context, ConjurAuthnInfo conjurAuthn) {
		LOGGER.log(Level.FINE, "Start of setConjurAuthnForJITCredentialAccess()");
		String token = "";
		token = JwtToken.getToken(context);
		GlobalConjurConfiguration globalconfig = GlobalConfiguration.all().get(GlobalConjurConfiguration.class);
		LOGGER.log(Level.FINE, "setConjurAuthnForJITCredentialAccess >>>" + token);

		if (token != null && globalconfig != null) {
			conjurAuthn.login = null;
			conjurAuthn.authnPath = globalconfig.getAuthWebServiceId();
			conjurAuthn.apiKey = "jwt=" + token;
			LOGGER.log(Level.FINE, "setConjurAuthnForJITCredentialAccess apikey= >>>" + conjurAuthn.apiKey);
		}
		LOGGER.log(Level.FINE, "End of setConjurAuthnForJITCredentialAccess()");
	}

	@SuppressFBWarnings
	public static String getSecret(OkHttpClient client, ConjurConfiguration configuration, String authToken,
			String variablePath) throws IOException {
		LOGGER.log(Level.FINE, "Start of getSecret()");
		String result = null;

		ConjurAuthnInfo conjurAuthn = getConjurAuthnInfo(configuration, null, null);

		LOGGER.log(Level.FINEST, "Fetching secret from Conjur" + variablePath);
		LOGGER.log(Level.FINEST, "Fetch token from Conjur"+authToken);
		Request request = new Request.Builder().url(
				String.format("%s/secrets/%s/variable/%s", conjurAuthn.applianceUrl, conjurAuthn.account, variablePath))
				.get().addHeader("Authorization", "Token token=\"" + authToken + "\"").build();

		Response response = client.newCall(request).execute();
		result = response.body().string();
		LOGGER.log(Level.FINEST, () -> "Fetch secret [" + variablePath + "] from Conjur response " + response.code()
				+ " - " + response.message());
		if (response.code() != 200) {
			throw new IOException("Error fetching secret from Conjur [" + response.code() + " - " + response.message()
					+ "\n" + result);
		}
		
		LOGGER.log(Level.FINE, "End of getSecret()");
		return result;
	}

	public static ConjurConfiguration logConjurConfiguration(ConjurConfiguration conjurConfiguration) {
		if (conjurConfiguration != null) {
			LOGGER.log(Level.FINEST, "Conjur configuration provided");
			LOGGER.log(Level.FINEST, "Conjur Configuration Appliance Url: " + conjurConfiguration.getApplianceURL());
			LOGGER.log(Level.FINEST, "Conjur Configuration Account: " + conjurConfiguration.getAccount());
			LOGGER.log(Level.FINEST, "Conjur Configuration credential ID: " + conjurConfiguration.getCredentialID());
		}
		return conjurConfiguration;
	}

	private static void initializeWithCredential(ConjurAuthnInfo conjurAuthn, String credentialID,
			List<UsernamePasswordCredentials> availableCredentials) {
		LOGGER.log(Level.FINE, "Start of initializeWithCredential()");
		if (credentialID != null && !credentialID.isEmpty()) {
			LOGGER.log(Level.FINEST, "Retrieving Conjur credential stored in Jenkins");
			UsernamePasswordCredentials credential = CredentialsMatchers.firstOrNull(availableCredentials,
					CredentialsMatchers.withId(credentialID));
			if (credential != null) {
				conjurAuthn.login = credential.getUsername();
				conjurAuthn.apiKey = credential.getPassword().getPlainText();
			}
		}
		LOGGER.log(Level.FINE, "End of initializeWithCredential()");
	}

	public static ConjurConfiguration getConfigurationFromContext(ModelObject context, ModelObject storeContext) {

		LOGGER.log(Level.FINE, "Start of getConfigurationFromContext()");
		ModelObject effectiveContext = context != null ? context : storeContext;

		Item contextObject = null;
		ConjurJITJobProperty conjurJobConfig = null;

		if (effectiveContext instanceof Run) {
			Run run = (Run) effectiveContext;
			conjurJobConfig = (ConjurJITJobProperty) run.getParent().getProperty(ConjurJITJobProperty.class);
			contextObject = run.getParent();
		} else if (effectiveContext instanceof AbstractItem) {
			contextObject = (Item) effectiveContext;
		}

		ConjurConfiguration conjurConfig = GlobalConjurConfiguration.get().getConjurConfiguration();

		if (effectiveContext == null) {
			return ConjurAPI.logConjurConfiguration(conjurConfig);
		}

		if (conjurJobConfig != null && !conjurJobConfig.getInheritFromParent()) {
			// Taking the configuration from the Job
			return ConjurAPI.logConjurConfiguration(conjurJobConfig.getConjurConfiguration());
		}

		ConjurConfiguration inheritedConfig = inheritedConjurConfiguration(contextObject);
		if (inheritedConfig != null) {
			return ConjurAPI.logConjurConfiguration(inheritedConfig);
		}
		LOGGER.log(Level.FINE, "End of getConfigurationFromContext()");
		return ConjurAPI.logConjurConfiguration(conjurConfig);

	}

	@SuppressWarnings("unchecked")
	private static ConjurConfiguration inheritedConjurConfiguration(Item job) {
		for (ItemGroup<? extends Item> g = job !=null?
				job.getParent():null; g instanceof AbstractFolder; g = ((AbstractFolder<? extends Item>) g).getParent()) {
			FolderConjurConfiguration fconf = ((AbstractFolder<?>) g).getProperties()
					.get(FolderConjurConfiguration.class);
			if (!(fconf == null || fconf.getInheritFromParent())) {
				// take the folder Conjur Configuration
				return fconf.getConjurConfiguration();
			}
		}
		return null;
	}

	private ConjurAPI() {
		super();
	}

}
