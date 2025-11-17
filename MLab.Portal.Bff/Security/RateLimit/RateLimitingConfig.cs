namespace MLab.Portal.Bff.Security.RateLimit;

/// <summary>
/// Strongly-typed configuration for the ASP.NET Core Rate Limiting middleware.
/// 
/// Moving these settings to configuration allows different environments to define
/// different rate limits without modifying or recompiling the application.
/// This also centralizes throttling behavior into a single clear configuration model.
/// </summary>
public class RateLimitingConfig
{
    public int PermitLimit { get; set; } = 30;
    public int WindowSeconds { get; set; } = 60;
    public int QueueLimit { get; set; } = 5;
}
