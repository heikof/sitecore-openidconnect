using System.Text;
using System.Web;
using Sitecore.Security.Authentication;
using Sitecore.Web;

namespace SC.OpenIdConnect
{
    public static class AuthenticationHelper
    {
        public static void Logout(string redirectUrl)
        {
            HttpContext.Current.Response.Cache.SetCacheability(HttpCacheability.NoCache);
            HttpContext.Current.Response.Cache.SetNoStore();

            AuthenticationManager.Logout();
            if (HttpContext.Current.Session != null)
            {
                HttpContext.Current.Session.Abandon();
                HttpContext.Current.Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", string.Empty));
            }

            var idToken = ""; // TODO get this from the original claim

            // Build logout URL
            var sb = new StringBuilder(Settings.LogoutEndpoint)
                .Append($"?id_token_hint={idToken}")
                .Append($"?post_logout_redirect_uri={redirectUrl}");

            WebUtil.Redirect(sb.ToString());
        }
    }
}
