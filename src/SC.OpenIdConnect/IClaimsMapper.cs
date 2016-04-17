using System.Security.Claims;

namespace SC.OpenIdConnect
{
    public interface IClaimsMapper
    {
        /// <summary>
        /// Maps a claims principal to an IUserClaims
        /// </summary>
        /// <param name="claimsPrincipal">Claims principal</param>
        /// <returns>An object of type IUserClaims</returns>
        IUserClaims Map(ClaimsPrincipal claimsPrincipal);
    }    
}
