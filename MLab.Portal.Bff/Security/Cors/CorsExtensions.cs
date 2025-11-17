namespace MLab.Portal.Bff.Security.Cors;

/// <summary>
/// Provides extension methods to configure CORS policies for the API.
/// </summary>
public static class CorsExtensions
{
    /// <summary>
    /// Registers the application's CORS policy using allowed origins defined in appsettings.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="config">The application configuration.</param>
    /// <returns>The same IServiceCollection instance.</returns>
    public static IServiceCollection AddAppCors(
        this IServiceCollection services,
        IConfiguration config)
    {
        var allowedOrigins = config
            .GetSection("Cors:AllowedOrigins")
            .Get<string[]>() ?? [];

        services.AddCors(options =>
        {
            options.AddPolicy("app", policy =>
                policy
                    .WithOrigins(allowedOrigins)
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials()
            );
        });

        return services;
    }
}
