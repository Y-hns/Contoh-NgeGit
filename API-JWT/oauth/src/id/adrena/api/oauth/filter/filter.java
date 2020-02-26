package id.adrena.api.oauth.filter;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import javax.xml.ws.soap.AddressingFeature.Responses;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

import id.adrena.api.oauth.model.SessionResult;

@Provider
public class filter implements ContainerRequestFilter{

	private static final String UNSECURED_URL = "session";
	private static final String UNSECURED_URL_2 = ".well-known";
	private static final String UNSECURED_URL_3 = "refresh";
	
	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		SessionResult result = null;
		if (requestContext.getUriInfo().getPath().contains(UNSECURED_URL)
				|| requestContext.getUriInfo().getPath().contains(UNSECURED_URL_2)
				|| requestContext.getUriInfo().getPath().contains(UNSECURED_URL_3)){
			return;
		}
		
		List<String> authHeader = requestContext.getHeaders().get("Authorization");
		
		if(authHeader != null && authHeader.size() > 0) {
			String authorization = authHeader.get(0);
			StringTokenizer tokenizer = new StringTokenizer(authorization, " ");
			
			try {
				String authType = tokenizer.nextToken();
				String token = tokenizer.nextToken();
				JWTClaimsSet set = Verifier.getJWTClaim(token);
				if(authType.equals("Bearer") && set != null) {
					return; //verifikasi berhasil
				}
			} catch (NoSuchElementException e) { //Mengikuti Throws dari tokenizer
				result = new SessionResult()
						.withHttpStatus(Response.Status.BAD_REQUEST)
						.withResultSuccess(0)
						.withErrorMessage("Invalid Authorization Header");
			} catch (ParseException | BadJOSEException | JOSEException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				
				if(e.getMessage().contains("Expired JWT")) {
					result = new SessionResult()
							.withHttpStatus(Response.Status.UNAUTHORIZED)
							.withResultSuccess(0)
							.withErrorMessage("Expired Token");
				} else {
					result = new SessionResult()
							.withHttpStatus(Response.Status.BAD_REQUEST)
							.withResultSuccess(0)
							.withErrorMessage("Invalid Token");
				}
			} 
		} else {
			result = new SessionResult()
					.withHttpStatus(Response.Status.BAD_REQUEST)
					.withResultSuccess(0)
					.withErrorMessage("Invalid Authorization Header");
		}
		
		requestContext.abortWith(
				Response
				.status(result.getHttpStatus())
				.entity(result)
				.build());
	}
	

}
