namespace MLab.Portal.Bff.Security.OidcAuthentication;

/// <summary>
/// Represents the strongly-typed configuration for a single OpenID Connect (OIDC)
/// laboratory provider. Each lab corresponds to a tenant/identity provider configured 
/// under the AuthenticationLabs section in appsettings.json.
/// 
/// Strong typing provides better safety, easier validation, and clearer error reporting,
/// compared to accessing configuration via raw strings or dictionaries.
/// </summary>


public class AuthConfig
{
    public string Authority { get; set; }
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
}
