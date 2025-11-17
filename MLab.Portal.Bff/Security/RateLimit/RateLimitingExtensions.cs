using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

namespace MLab.Portal.Bff.Security.RateLimit;

/// <summary>
/// Configures the ASP.NET Core Rate Limiter middleware using strongly-typed settings
/// loaded from the RateLimit section of appsettings.json.
/// 
/// Extracting this logic into an extension method keeps Program.cs clean,
/// enables environment-specific throttling, and makes rate limiting behavior
/// explicit and easy to adjust without code changes.
/// </summary>
public static class RateLimitingExtensions
{
    public static IServiceCollection AddRateLimiting(
        this IServiceCollection services,
        IConfiguration config)
    {
        var rl = config.GetSection("RateLimit").Get<RateLimitingConfig>()
                 ?? new RateLimitingConfig();

        services.AddRateLimiter(options =>
        {
            options.AddFixedWindowLimiter("default", limiter =>
            {
                limiter.PermitLimit = rl.PermitLimit;
                limiter.Window = TimeSpan.FromSeconds(rl.WindowSeconds);
                limiter.QueueLimit = rl.QueueLimit;
                limiter.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
            });
        });

        return services;
    }
}
