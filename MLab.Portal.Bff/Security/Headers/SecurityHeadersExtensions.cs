using Microsoft.AspNetCore.Builder;

namespace MLab.Portal.Bff.Security.Headers;

/// <summary>
/// Adds a baseline set of security headers to every HTTP response.
/// These headers harden the BFF against common web vulnerabilities such as
/// MIME sniffing, clickjacking, cache poisoning, and referrer leakage.
/// 
/// Extracting this into a middleware extension keeps Program.cs clean and 
/// guarantees consistent security behavior across environments.
/// </summary>


public static class SecurityHeadersExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
    {
        return app.Use(async (ctx, next) =>
        {
            var h = ctx.Response.Headers;
            h["X-Frame-Options"] = "DENY";
            h["X-Content-Type-Options"] = "nosniff";
            h["Referrer-Policy"] = "strict-origin-when-cross-origin";
            h["Cache-Control"] = "no-store, no-cache, must-revalidate";
            h["Pragma"] = "no-cache";
            h["Expires"] = "0";

            await next();
        });
    }
}
