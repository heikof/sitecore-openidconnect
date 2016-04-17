namespace SC.OpenIdConnect
{
    public static class Settings
    {
        public static string SignInCallbackUrl => Sitecore.Configuration.Settings.GetSetting("OpenIdConnect.SignInCallbackUrl");

        public static string PublicKey => Sitecore.Configuration.Settings.GetSetting("OpenIdConnect.PublicKey");

        public static string TempCookieName => Sitecore.Configuration.Settings.GetSetting("OpenIdConnect.TempCookieName", "TempCookie");

        public static string Scope => Sitecore.Configuration.Settings.GetSetting("OpenIdConnect.Scope", "openid profile roles all_claims");

        public static string ClientId => Sitecore.Configuration.Settings.GetSetting("OpenIdConnect.ClientId");

        public static string ValidIssuer => Sitecore.Configuration.Settings.GetSetting("OpenIdConnect.ValidIssuer");

        public static string AuthorizeEndpoint => Sitecore.Configuration.Settings.GetSetting("OpenIdConnect.AuthorizeEndpoint");

        public static string LogoutEndpoint => Sitecore.Configuration.Settings.GetSetting("OpenIdConnect.LogoutEndpoint");
    }
}
