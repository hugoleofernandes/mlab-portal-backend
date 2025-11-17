namespace MLab.Portal.Bff.Configuration;

/// <summary>
/// Represents frontend-related configuration consumed by the BFF. This includes the base
/// URL used to redirect the user after authentication or logout.
/// 
/// Keeping this in a dedicated configuration class centralizes all frontend integration
/// settings, improves clarity, and enables environment-specific frontend URL mapping.
/// </summary>


public class FrontendConfig
{
    public string BaseUrl { get; set; }
}
