using Microsoft.AspNetCore.HttpOverrides;

namespace MLab.Portal.Bff.Security.Headers;

/// <summary>
/// Applies default forwarded headers needed when running behind
/// reverse proxies such as ngrok, Azure Container Apps, ingress controllers,
/// or load balancers.
/// 
/// This method keeps Program.cs clean while preserving readability.
/// </summary>
public static class ForwardedHeadersExtensions
{
    public static IApplicationBuilder UseForwardedHeadersDefaults(this IApplicationBuilder app)
    {
        var options = new ForwardedHeadersOptions
        {
            ForwardedHeaders =
                ForwardedHeaders.XForwardedFor |
                ForwardedHeaders.XForwardedProto
        };

        // Allow all networks (ideal for ngrok, Azure, containers)
        options.KnownNetworks.Clear();
        options.KnownProxies.Clear();

        return app.UseForwardedHeaders(options);
    }
}
