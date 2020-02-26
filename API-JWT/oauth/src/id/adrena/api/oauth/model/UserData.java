package id.adrena.api.oauth.model;

public class UserData {

	private int userId;
	private String userType;
	private String email;
	private String password;
	
	public UserData(int userId, String userType, String email, String password) {
		super();
		this.userId = userId;
		this.userType = userType;
		this.email = email;
		this.password = password;
	}
	
	public UserData() {
		super();
		// TODO Auto-generated constructor stub
	}
	
	public int getUserId() {
		return userId;
	}
	public void setUserId(int userId) {
		this.userId = userId;
	}
	public String getUserType() {
		return userType;
	}
	public void setUserType(String userType) {
		this.userType = userType;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	
	
}
