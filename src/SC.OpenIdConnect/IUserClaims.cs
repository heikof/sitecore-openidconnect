using System.Collections.Generic;

namespace SC.OpenIdConnect
{
    public interface IUserClaims
    {
        /// <summary>
        /// Gets or sets user application domain
        /// </summary>
        string Domain { get; set; }

        /// <summary>
        /// Gets or sets user identifier
        /// </summary>
        string UserId { get; set; }

        /// <summary>
        /// Gets or sets user roles
        /// </summary>
        IEnumerable<string> Roles { get; set; }
    }
}
