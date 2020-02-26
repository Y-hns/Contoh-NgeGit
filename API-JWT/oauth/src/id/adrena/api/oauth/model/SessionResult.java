package id.adrena.api.oauth.model;

import javax.json.bind.annotation.JsonbTransient;
import javax.ws.rs.core.Response;

public class SessionResult {

	@JsonbTransient
	private int httpStatus; //Supaya java tidak mencetak httpstatus di json
	
	private int resultSuccess;
	private String errorMessage;
	
	private Token token;

	
	public SessionResult(int httpStatus, int resultSuccess, String errorMessage, Token token) {
		super();
		this.httpStatus = httpStatus;
		this.resultSuccess = resultSuccess;
		this.errorMessage = errorMessage;
		this.token = token;
	}

	
	
	public SessionResult() {
		super();
		// TODO Auto-generated constructor stub
	}

	
	
	public int getHttpStatus() {
		return httpStatus;
	}

	public void setHttpStatus(int httpStatus) {
		this.httpStatus = httpStatus;
	}

	public int getResultSuccess() {
		return resultSuccess;
	}

	public void setResultSuccess(int resultSuccess) {
		this.resultSuccess = resultSuccess;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	public Token getToken() {
		return token;
	}

	public void setToken(Token token) {
		this.token = token;
	}
	
	
	public SessionResult withHttpStatus(Response.Status status) {
		this.httpStatus = status.getStatusCode();
		return this;
	}
	
	public SessionResult withResultSuccess(int resultSuccess) {
		this.resultSuccess = resultSuccess;
		return this;
	}
	
	public SessionResult withErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
		return this;
	}
	
	public SessionResult withToken(Token token) {
		this.token = token;
		return this;
	}
	
}
