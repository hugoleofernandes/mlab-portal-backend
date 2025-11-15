using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using MLab.Portal.Bff.Security.Csrf;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.RateLimiting;

IdentityModelEventSource.ShowPII = Debugger.IsAttached;

var builder = WebApplication.CreateBuilder(args);

//
// ==================== CORS ====================
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

builder.Services.AddHttpContextAccessor();

//
// ==================== AUTENTICAÇÃO (MULTI-SCHEME) ====================
//
var uiLocales = builder.Configuration.GetSection("Authentication")["UiLocales"] ?? "pt-BR";

var lab1Cfg = builder.Configuration.GetSection("AuthenticationLabs:lab1");
var lab2Cfg = builder.Configuration.GetSection("AuthenticationLabs:lab2");

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
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
    .AddOpenIdConnect("lab1", opt => ConfigureLabScheme(opt, lab1Cfg, uiLocales, "lab1"))
    .AddOpenIdConnect("lab2", opt => ConfigureLabScheme(opt, lab2Cfg, uiLocales, "lab2"));

//
// ==================== MVC + RATE LIMITER + SWAGGER ====================
//
builder.Services.AddAuthorization();
builder.Services.AddControllers(o => o.Filters.Add<ValidateAntiCsrfFilter>());

builder.Services.AddRateLimiter(_ => _.AddFixedWindowLimiter("default", o =>
{
    o.PermitLimit = 30;
    o.Window = TimeSpan.FromMinutes(1);
    o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    o.QueueLimit = 5;
}));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddApplicationInsightsTelemetry();

var app = builder.Build();

//
// ==================== FORWARDED HEADERS ====================
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedFor,
    RequireHeaderSymmetry = false,
    ForwardLimit = null,
    KnownNetworks = { },
    KnownProxies = { }
});

//
// ==================== SWAGGER ====================
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

//
// ==================== CABEÇALHOS DE SEGURANÇA ====================
app.Use((context, next) =>
{
    var h = context.Response.Headers;
    h["X-Frame-Options"] = "DENY";
    h["X-Content-Type-Options"] = "nosniff";
    h["Referrer-Policy"] = "strict-origin-when-cross-origin";
    h["Cache-Control"] = "no-store, no-cache, must-revalidate";
    h["Pragma"] = "no-cache";
    h["Expires"] = "0";

    return next();
});

if (!app.Environment.IsDevelopment())
    app.UseHsts();

//
// ==================== PIPELINE ====================
app.UseRateLimiter();
app.UseCors("app");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();


//
// ======================================================================
// ============ FUNÇÃO CENTRAL PARA CONFIGURAR CADA SCHEME OIDC =========
// ======================================================================
static void ConfigureLabScheme(OpenIdConnectOptions options, IConfiguration cfg, string uiLocales, string labName)
{
    var authority = cfg["Authority"];
    var clientId = cfg["ClientId"];
    var clientSecret = cfg["ClientSecret"];

    if (string.IsNullOrWhiteSpace(authority) || string.IsNullOrWhiteSpace(clientId))
        throw new InvalidOperationException("Configuração inválida: Authority ou ClientId ausentes.");

    options.Authority = authority;
    options.ClientId = clientId;
    options.ClientSecret = clientSecret;

    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true;

    // Callback único para todos os labs
    //options.CallbackPath = "/signin-oidc";
    //options.SignedOutCallbackPath = "/signout-callback-oidc";

    options.GetClaimsFromUserInfoEndpoint = true;
    options.SaveTokens = false;

    // Scopes
    options.Scope.Clear();
    foreach (var s in ("openid profile email").Split(' ', StringSplitOptions.RemoveEmptyEntries))
        options.Scope.Add(s.Trim());

    // Claims
    options.TokenValidationParameters.NameClaimType = "name";
    options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;

    // Callback 
    options.CallbackPath = $"/signin-oidc/{labName}";
    options.SignedOutCallbackPath = $"/signout-callback-oidc/{labName}";

    //
    // ==================== EVENTOS PERSONALIZADOS ====================
    //
    options.Events = new OpenIdConnectEvents
    {
        //
        // ----- LOGIN -----
        //
        OnRedirectToIdentityProvider = ctx =>
        {
            var http = ctx.HttpContext;
            var labName = ctx.Scheme.Name.ToLowerInvariant(); // lab1 ou lab2

            // Cookie com o nome do lab
            http.Response.Cookies.Append("mlab_lab", labName, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/"
            });

            // Ajuste do endpoint
            var issuer = authority.Replace("/v2.0", "/oauth2/v2.0/authorize");
            ctx.ProtocolMessage.AuthorizationEndpoint = authority;
            ctx.ProtocolMessage.IssuerAddress = issuer;
            ctx.ProtocolMessage.ClientId = clientId;
            ctx.ProtocolMessage.SetParameter("client_secret", clientSecret);

            // Forçar login SEM KMSI
            ctx.ProtocolMessage.Prompt = "login";
            ctx.ProtocolMessage.SetParameter("login_hint", "");
            ctx.ProtocolMessage.SetParameter("domain_hint", "none");
            ctx.ProtocolMessage.SetParameter("max_age", "0");
            ctx.ProtocolMessage.SetParameter("remember", "false");
            ctx.ProtocolMessage.SetParameter("suppress_prompt", "true");
            ctx.ProtocolMessage.SetParameter("auth_method", "refresh_session");
            ctx.ProtocolMessage.SetParameter("disable_kmsi", "true");
            ctx.ProtocolMessage.SetParameter("disable_kmsi", "1");

            // Idioma
            ctx.ProtocolMessage.SetParameter("ui_locales", uiLocales);
            ctx.ProtocolMessage.SetParameter("mkt", uiLocales);

            ctx.ProtocolMessage.ResponseMode = "query";

            Console.WriteLine($"🔹 Login: scheme={labName}");

            return Task.CompletedTask;
        },

        //
        // ----- LOGOUT -----
        //
        OnRedirectToIdentityProviderForSignOut = ctx =>
        {
            ctx.ProtocolMessage.SetParameter("ui_locales", uiLocales);
            ctx.ProtocolMessage.SetParameter("mkt", uiLocales);
            return Task.CompletedTask;
        },

        //
        // ----- TOKEN VALIDATED -----
        //
        OnTokenValidated = ctx =>
        {
            var http = ctx.HttpContext;
            var labName = ctx.Scheme.Name.ToLowerInvariant();

            // Claim com o lab
            if (ctx.Principal?.Identity is ClaimsIdentity id)
            {
                id.AddClaim(new Claim("mlab_lab", labName));
            }

            // XSRF-TOKEN
            var xsrfToken = Guid.NewGuid().ToString("N");
            http.Response.Cookies.Append("XSRF-TOKEN", xsrfToken, new CookieOptions
            {
                HttpOnly = false,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/"
            });

            Console.WriteLine($"🔹 Token validado: scheme={labName}");

            return Task.CompletedTask;
        }
    };
}
