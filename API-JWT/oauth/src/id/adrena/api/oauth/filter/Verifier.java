package id.adrena.api.oauth.filter;

import java.io.IOException;
import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import id.adrena.api.oauth.utils.JWKUtils;

public class Verifier {
	
	private static JWKSource<SecurityContext> getJWKS() throws IOException, ParseException { //fungsi untuk mengambil jwk
		JWKSource<SecurityContext> key = new ImmutableJWKSet<SecurityContext>(JWKUtils.getSigningSet());
		return key;
	}
	
	private static JWSKeySelector<SecurityContext> getKey(JWSAlgorithm algorithm, JWKSource<SecurityContext> jwkSource) { //fungsi untuk mengambil key
		return new JWSVerificationKeySelector<>(algorithm, jwkSource);
	}

	public static JWTClaimsSet getJWTClaim(String token) throws IOException, ParseException, BadJOSEException, JOSEException { //untuk verifikasi dan juga mengambil claim
		//verifikasi JWT(Verifikasi Struktur dan signature JWT)
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<SecurityContext>();
		jwtProcessor.setJWSKeySelector(getKey(JWSAlgorithm.RS256, getJWKS()));
		
		//ambil claim dari JWT
		JWTClaimsSet set = jwtProcessor.process(token, null);
		
		return set;
	}
}
