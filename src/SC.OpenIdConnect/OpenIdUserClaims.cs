using System.Collections.Generic;

namespace SC.OpenIdConnect
{
    public class OpenIdUserClaims : IUserClaims
    {
        public string Domain { get; set; }
        public string UserId { get; set; }
        public IEnumerable<string> Roles { get; set; }
    }
}