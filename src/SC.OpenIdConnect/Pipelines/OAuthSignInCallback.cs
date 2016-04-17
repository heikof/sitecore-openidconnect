using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using Microsoft.Practices.ServiceLocation;
using Sitecore;
using Sitecore.Pipelines.HttpRequest;
using Sitecore.Security;
using Sitecore.Security.Accounts;
using Sitecore.Security.Authentication;
using Sitecore.Web;
using Convert = System.Convert;

namespace SC.OpenIdConnect.Pipelines
{
    public class OAuthSignInCallback : HttpRequestProcessor
    {
        public override void Process(HttpRequestArgs args)
        {
            // NOTE - no error handling added. Failed requests are expected to result in an unhandled exception. 

            // Only act on unauthenticated requests against the sign-in callback URL
            if (Context.User == null || Context.User.IsAuthenticated ||
                Context.User.Identity.GetType() == typeof(UserProfile) ||
                !args.Context.Request.Url.AbsoluteUri.StartsWith(Settings.SignInCallbackUrl)) return;

            // Validate token and construct claims prinicpal / session security token
            var tempCookie = args.Context.Request.Cookies[Settings.TempCookieName];
            var claims = ValidateIdentityToken(args.Context.Request.Form["id_token"], args.Context.Request.Form["state"], tempCookie);
            var identity = new ClaimsIdentity(claims, "Forms", ClaimTypes.Name, ClaimTypes.Role);
            var principal = new ClaimsPrincipal(identity);
            var sessionSecurityToken = new SessionSecurityToken(principal);

            // Build sitecore user and log in 
            var user = BuildUser(sessionSecurityToken);
            AuthenticationManager.LoginVirtualUser(user);

            if (tempCookie != null)
            {
                tempCookie.Expires = DateTime.Now.AddDays(-1);
                args.Context.Response.Cookies.Add(tempCookie);
            }
            var targetUrl = tempCookie?.Values["returnUrl"] ?? "/";
            WebUtil.Redirect(targetUrl);
        }

        // ReSharper disable once UnusedParameter.Local - state is used in validation against cookie value
        private IEnumerable<Claim> ValidateIdentityToken(string token, string state, HttpCookie tempCookie)
        {
            if (tempCookie == null)
                throw new InvalidOperationException("Could not validate identity token. No temp cookie found.");

            if (string.IsNullOrWhiteSpace(tempCookie.Values["state"]) || tempCookie.Values["state"] != state)
                throw new InvalidOperationException("Could not validate identity token. Invalid state.");

            var cert = new X509Certificate2(Convert.FromBase64String(Settings.PublicKey));

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidAudience = Settings.ClientId,
                ValidIssuer = Settings.ValidIssuer,
                IssuerSigningToken = new X509SecurityToken(cert)
            };

            var handler = new JwtSecurityTokenHandler();
            SecurityToken jwt;
            var id = handler.ValidateToken(token, tokenValidationParameters, out jwt);
            if (string.IsNullOrWhiteSpace(tempCookie.Values["nonce"]) || id.FindFirst("nonce").Value != tempCookie.Values["nonce"])
                throw new InvalidOperationException("Could not validate identity token. Invalid nonce");

            return id.Claims;
        }

        private User BuildUser(SessionSecurityToken sessionToken)
        {
            var claimsProcessor = ServiceLocator.Current.GetInstance<IClaimsMapper>();
            var userClaims = claimsProcessor.Map(sessionToken.ClaimsPrincipal);
            var username = $"{userClaims.Domain}\\{userClaims.UserId}";
            var user = AuthenticationManager.BuildVirtualUser(username, true);
            AssignUserRoles(user, userClaims);
            return user;
        }

        private void AssignUserRoles(User user, IUserClaims claimsUser)
        {
            user.RuntimeSettings.AddedRoles.Clear();
            user.Roles.RemoveAll();

            foreach (var role in claimsUser.Roles.Where(Role.Exists))
            {
                user.Roles.Add(Role.FromName(role));
            }
        }
    }
}
