package id.adrena.api.oauth.endpoint;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import id.adrena.api.oauth.model.UserData;

@Path("user")
public class UserEndpoint {

	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response getUser() {
		return Response
				.status(Response.Status.OK)
				.entity(new UserData(1, "common", "user@auth.com", null))
				.build(); //null = password
	}
}
