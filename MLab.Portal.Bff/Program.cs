using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Logging;
using MLab.Portal.Bff.Security.Csrf;
using System.Security.Claims;
using System.Threading.RateLimiting;
using System.Diagnostics;

// Exibe detalhes PII apenas no modo Debug
IdentityModelEventSource.ShowPII = Debugger.IsAttached;

var builder = WebApplication.CreateBuilder(args);

//
// Configuração de CORS
//
var allowedOrigins = builder.Configuration
    .GetSection("Cors:AllowedOrigins")
    .Get<string[]>() ?? Array.Empty<string>();

builder.Services.AddCors(opt =>
{
    opt.AddPolicy("app", p => p
        .WithOrigins(allowedOrigins)
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials());
});

//
// Autenticação e Cookie Seguro
//
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.Name = ".mlab.portal.session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.None;
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    })
    .AddOpenIdConnect(options =>
    {
        // Valores padrões apenas para inicialização (serão substituídos)
        var cfg = builder.Configuration.GetSection("Authentication");

        options.Authority = cfg["Authority"] ?? "https://placeholder.ciamlogin.com/placeholder.onmicrosoft.com/v2.0";
        options.ClientId = cfg["ClientId"] ?? "00000000-0000-0000-0000-000000000000";
        options.ClientSecret = cfg["ClientSecret"] ?? "dummy-secret";
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;

        options.CallbackPath = cfg["CallbackPath"];
        options.SignedOutCallbackPath = cfg["SignedOutCallbackPath"];
        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = false;

        // Escopos padrão
        options.Scope.Clear();
        foreach (var s in (cfg["Scopes"] ?? "openid profile email").Split(' ', StringSplitOptions.RemoveEmptyEntries))
            options.Scope.Add(s);

        // Claims padrão
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;

        var ui = cfg["UiLocales"];

        //
        // === Eventos personalizados ===
        //
        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = ctx =>
            {
                var http = ctx.HttpContext;

                // Lê lab da querystring
                var lab = http.Request.Query["lab"].ToString()?.ToLowerInvariant();
                if (string.IsNullOrWhiteSpace(lab))
                {
                    http.Response.StatusCode = 400;
                    return http.Response.WriteAsync("Erro: parâmetro 'lab' é obrigatório (ex: /auth/login?lab=lab1)");
                }

                var labConfig = builder.Configuration.GetSection($"AuthenticationLabs:{lab}");
                var authority = labConfig["Authority"];
                var clientId = labConfig["ClientId"];
                var clientSecret = labConfig["ClientSecret"];

                if (string.IsNullOrEmpty(authority) || string.IsNullOrEmpty(clientId))
                {
                    http.Response.StatusCode = 400;
                    return http.Response.WriteAsync($"Erro: laboratório '{lab}' não possui configuração válida.");
                }

                // Ajuste do Authority (sem duplicar /v2.0)
                var issuer = authority.Replace("/v2.0", "/oauth2/v2.0/authorize");

                ctx.ProtocolMessage.IssuerAddress = issuer;
                ctx.ProtocolMessage.ClientId = clientId;
                ctx.ProtocolMessage.SetParameter("client_secret", clientSecret);

                // Idioma e experiência de login
                ctx.ProtocolMessage.SetParameter("ui_locales", ui);
                ctx.ProtocolMessage.SetParameter("mkt", ui);

                // Força reautenticação e ignora prompt "Continuar conectado?"
                // sempre exibir tela de login
                ctx.ProtocolMessage.Prompt = "login";
                // ignora sessão anterior
                ctx.ProtocolMessage.SetParameter("domain_hint", "none");
                // não sugere usuário anterior
                ctx.ProtocolMessage.SetParameter("login_hint", "");
                // força revalidação imediata
                ctx.ProtocolMessage.SetParameter("max_age", "0");
                // impede “Continuar conectado?”
                ctx.ProtocolMessage.SetParameter("remember", "false");   


                Console.WriteLine($"🔹 Tenant ativo: {lab} ({authority})");
                return Task.CompletedTask;
            },

            OnRedirectToIdentityProviderForSignOut = ctx =>
            {
                ctx.ProtocolMessage.SetParameter("ui_locales", ui);
                ctx.ProtocolMessage.SetParameter("mkt", ui);
                return Task.CompletedTask;
            },

            OnTokenValidated = ctx =>
            {
                var http = ctx.HttpContext;
                var xsrfToken = Guid.NewGuid().ToString("N");

                http.Response.Cookies.Append("XSRF-TOKEN", xsrfToken, new CookieOptions
                {
                    HttpOnly = false,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Path = "/"
                });

                var user = ctx.Principal?.Identity?.Name ?? "Desconhecido";
                var logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Login");
                logger.LogInformation("Token XSRF criado para {User} em {Time}", user, DateTimeOffset.UtcNow);

                return Task.CompletedTask;
            }
        };
    });

//
// Autorização + MVC + Swagger + Application Insights
//
builder.Services.AddAuthorization();

builder.Services.AddControllers(options =>
{
    options.Filters.Add<ValidateAntiCsrfFilter>();
});

builder.Services.AddRateLimiter(_ => _
    .AddFixedWindowLimiter("default", options =>
    {
        options.PermitLimit = 30;
        options.Window = TimeSpan.FromMinutes(1);
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        options.QueueLimit = 5;
    })
);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddApplicationInsightsTelemetry();

var app = builder.Build();

Console.WriteLine($"ASP.NET iniciado em ambiente: {builder.Environment.EnvironmentName}");
Console.WriteLine($"URLs: {builder.Configuration["ASPNETCORE_URLS"] ?? "default"}");

//
// Pipeline de execução
//
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

//
// Segurança de cabeçalhos HTTP
//
app.Use((context, next) =>
{
    var headers = context.Response.Headers;

    headers["X-Frame-Options"] = "DENY";
    headers["X-Content-Type-Options"] = "nosniff";
    headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    headers["X-XSS-Protection"] = "1; mode=block";
    headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    headers["Pragma"] = "no-cache";
    headers["Expires"] = "0";

    headers["Content-Security-Policy"] =
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: https://*.microsoft.com; " +
        "frame-ancestors 'none'; " +
        "object-src 'none'; " +
        "base-uri 'self';";

    return next();
});

if (!app.Environment.IsDevelopment())
    app.UseHsts();

app.UseRateLimiter();
app.UseCors("app");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();