using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;

namespace MLab.Portal.Bff.Security.OidcAuthentication;

/// <summary>
/// Centralizes all OpenID Connect configuration for each lab (tenant).
/// 
/// Responsibilities:
/// - Point the BFF to the correct identity provider for each lab.
/// - Generate the correct callback and logout URLs dynamically.
/// - Apply security hardening (PKCE, no KMSI, no silent login, forced prompt).
/// - Emit custom claims such as "mlab_lab".
/// - Write cross-tenant cookies to ensure logout and token flow.
/// - Allow dynamic onboarding of new labs by updating appsettings.json only.
/// 
/// This class is the heart of the multi-tenant authentication design.
/// </summary>
public static class OidcMultiTenantConfigurator
{
    public static void Configure(
        OpenIdConnectOptions options,
        IConfiguration authCfg,
        AuthConfig lab,
        string uiLocales,
        string labName)
    {
        //
        // ==================== BASIC OIDC CONFIG ====================
        //
        options.Authority = lab.Authority;
        options.ClientId = lab.ClientId;
        options.ClientSecret = lab.ClientSecret;

        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;

        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = false;


        //
        // ==================== SCOPES ====================
        //
        options.Scope.Clear();

        var rawScopes = authCfg["Scopes"] ?? "openid profile email";
        foreach (var scope in rawScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            options.Scope.Add(scope);


        //
        // ==================== CLAIM RULES ====================
        //
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;


        //
        // ==================== CALLBACKS ====================
        //
        options.CallbackPath = authCfg["CallbackPath"]?.Replace("{lab}", labName);
        options.SignedOutCallbackPath = authCfg["SignedOutCallbackPath"]?.Replace("{lab}", labName);


        //
        // ==================== EVENTS ====================
        //
        options.Events = new OpenIdConnectEvents
        {
            //
            // ----- LOGIN REQUEST -----
            //
            OnRedirectToIdentityProvider = ctx =>
            {
                var http = ctx.HttpContext;
                var currentLab = ctx.Scheme.Name.ToLowerInvariant();

                // Cookie com o nome do lab selecionado
                http.Response.Cookies.Append("mlab_lab", currentLab, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Path = "/"
                });

                //
                // ----- Ajuste de endpoints do Hosted UI -----
                //
                var authority = lab.Authority;
                var issuer = authority.Replace("/v2.0", "/oauth2/v2.0/authorize");

                ctx.ProtocolMessage.AuthorizationEndpoint = authority;
                ctx.ProtocolMessage.IssuerAddress = issuer;
                ctx.ProtocolMessage.ClientId = lab.ClientId;
                ctx.ProtocolMessage.SetParameter("client_secret", lab.ClientSecret);

                //
                // ----- Forçar login SEM "Keep me signed in" -----
                //
                ctx.ProtocolMessage.Prompt = "login";
                ctx.ProtocolMessage.SetParameter("login_hint", "");
                ctx.ProtocolMessage.SetParameter("domain_hint", "none");
                ctx.ProtocolMessage.SetParameter("max_age", "0");
                ctx.ProtocolMessage.SetParameter("remember", "false");
                ctx.ProtocolMessage.SetParameter("suppress_prompt", "true");
                ctx.ProtocolMessage.SetParameter("auth_method", "refresh_session");
                ctx.ProtocolMessage.SetParameter("disable_kmsi", "true");
                ctx.ProtocolMessage.SetParameter("disable_kmsi", "1");

                //
                // ----- Idioma -----
                //
                ctx.ProtocolMessage.SetParameter("ui_locales", uiLocales);
                ctx.ProtocolMessage.SetParameter("mkt", uiLocales);

                ctx.ProtocolMessage.ResponseMode = "query";

                Console.WriteLine($"🔹 Redirecting to Hosted UI → Scheme={currentLab}");

                return Task.CompletedTask;
            },

            //
            // ----- LOGOUT REQUEST -----
            //
            OnRedirectToIdentityProviderForSignOut = ctx =>
            {
                ctx.ProtocolMessage.SetParameter("ui_locales", uiLocales);
                ctx.ProtocolMessage.SetParameter("mkt", uiLocales);
                return Task.CompletedTask;
            },

            //
            // ----- TOKEN RECEIVED -----
            //
            OnTokenValidated = ctx =>
            {
                var http = ctx.HttpContext;
                var currentLab = ctx.Scheme.Name.ToLowerInvariant();

                // adiciona a claim de tenant
                if (ctx.Principal?.Identity is ClaimsIdentity id)
                {
                    id.AddClaim(new Claim("mlab_lab", currentLab));
                }

                // XSRF token
                var xsrfToken = Guid.NewGuid().ToString("N");
                http.Response.Cookies.Append("XSRF-TOKEN", xsrfToken, new CookieOptions
                {
                    HttpOnly = false,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Path = "/"
                });

                Console.WriteLine($"🔹 Token validated → Scheme={currentLab}");

                return Task.CompletedTask;
            }
        };
    }
}
