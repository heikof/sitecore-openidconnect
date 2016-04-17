using System.Linq;
using System.Security.Claims;

namespace SC.OpenIdConnect
{
    public class OpenIdClaimsMapper : IClaimsMapper
    {
        public IUserClaims Map(ClaimsPrincipal claimsPrincipal)
        {
            return new OpenIdUserClaims
            {
                Domain = "extranet",
                UserId = claimsPrincipal.Claims.Single(c => c.Type.Equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")).Value,
                Roles = claimsPrincipal.Claims.Where(c => c.Type.Equals("http://schemas.microsoft.com/ws/2008/06/identity/claims/role")).Select(c => c.Value)
            };
        }
    }
}