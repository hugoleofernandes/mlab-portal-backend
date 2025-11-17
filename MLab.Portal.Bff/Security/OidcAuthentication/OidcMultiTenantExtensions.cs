using Microsoft.AspNetCore.Authentication.Cookies;

namespace MLab.Portal.Bff.Security.OidcAuthentication;

/// <summary>
/// Registers the authentication pipeline for the BFF (Backend-for-Frontend),
/// including the session cookie and all OpenID Connect (OIDC) providers (labs).
///
/// This component reads the AuthenticationLabs section from configuration and
/// dynamically registers one OIDC scheme for each lab defined. 
/// 
/// The goal is to support a multi-tenant authentication architecture where
/// new labs can be added simply by updating the appsettings.json — without
/// modifying Program.cs or recompiling the application.
/// 
/// By isolating all authentication concerns into this extension method, the 
/// Program.cs remains clean and the authentication logic becomes testable,
/// modular and easier to maintain.
/// </summary>

public static class OidcMultiTenantExtensions
{
    public static IServiceCollection AddOidcMultiTenantAuthentication(
        this IServiceCollection services,
        IConfiguration config)
    {
        var authCfg = config.GetSection("Authentication");
        var uiLocales = authCfg["UiLocales"] ?? "pt-BR";

        var labs = config.GetSection("AuthenticationLabs").Get<Dictionary<string, AuthConfig>>();

        var authBuilder = services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        });

        authBuilder.AddCookie(options =>
        {
            options.Cookie.Name = AuthConstants.SessionCookie;
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.None;
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            options.SlidingExpiration = true;
        });

        foreach (var (labName, labCfg) in labs)
        {
            authBuilder.AddOpenIdConnect(labName, options =>
            {
                OidcMultiTenantConfigurator.Configure(options, authCfg, labCfg, uiLocales, labName);
            });
        }

        return services;
    }
}
