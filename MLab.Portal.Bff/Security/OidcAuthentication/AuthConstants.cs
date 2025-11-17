namespace MLab.Portal.Bff.Security.OidcAuthentication;

/// <summary>
/// Defines application-wide constants used by the BFF, such as cookie names and
/// claim identifiers.
///
/// By centralizing these literals, we avoid hardcoding strings across the system,
/// prevent typos, and ensure consistent naming conventions throughout the application.
/// </summary>

public static class AuthConstants
{
    public const string SessionCookie = ".mlab.portal.session";
    public const string LabClaim = "mlab_lab";
}
