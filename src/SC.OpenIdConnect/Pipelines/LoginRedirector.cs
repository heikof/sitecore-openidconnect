using System;
using System.Text;
using System.Web;
using Sitecore;
using Sitecore.Pipelines.HttpRequest;
using Sitecore.Sites;
using Sitecore.Web;

namespace SC.OpenIdConnect.Pipelines
{
    public class LoginRedirector : HttpRequestProcessor
    {
        public override void Process(HttpRequestArgs args)
        {
            if (Context.Database == null || Context.Site == null) return;
            if (Context.User.IsAuthenticated) return;
            if (!SiteManager.CanEnter(Context.Site.Name, Context.User)) return;
            if (Context.Item != null && Context.Item.Access.CanRead()) return;
            if (Context.Item == null && args.PermissionDenied)
            {
                // generate nonces and set temporary cookie
                var state = Guid.NewGuid().ToString("N");
                var nonce = Guid.NewGuid().ToString("N");
                var cookie = new HttpCookie(Settings.TempCookieName);
                cookie.Values.Add("state", state);
                cookie.Values.Add("nonce", nonce);
                cookie.Values.Add("returnUrl", args.Context.Request.Url.ToString());
                args.Context.Response.Cookies.Add(cookie);

                // Redirect the user to the login page of the identity provider
                var sb = new StringBuilder(Settings.AuthorizeEndpoint)
                    .Append($"?client_id={Settings.ClientId}")
                    .Append($"&scope={Settings.Scope}")
                    .Append("&response_type=id_token&response_mode=form_post")
                    .Append($"&redirect_uri={Settings.SignInCallbackUrl}")
                    .Append($"&state={state}&nonce={nonce}");

                WebUtil.Redirect(sb.ToString());
            }
        }
    }
}