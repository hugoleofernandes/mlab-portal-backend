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
// CORS
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
// Autenticação + Cookie seguro
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
        //
        // VALORES DEFAULT APENAS PARA INICIALIZAÇÃO –
        // Eles serão SOBRESCRITOS conforme o lab selecionado
        //
        var cfg = builder.Configuration.GetSection("Authentication");

        options.Authority = cfg["Authority"];
        options.ClientId = cfg["ClientId"];
        options.ClientSecret = cfg["ClientSecret"];

        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;

        options.CallbackPath = cfg["CallbackPath"];
        options.SignedOutCallbackPath = cfg["SignedOutCallbackPath"];
        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = false;

        // Scopes
        options.Scope.Clear();
        foreach (var s in (cfg["Scopes"] ?? "openid profile email").Split(' '))
            if (!string.IsNullOrWhiteSpace(s))
                options.Scope.Add(s.Trim());

        // Claims
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;

        var ui = cfg["UiLocales"];

        //
        // EVENTOS PERSONALIZADOS
        //
        options.Events = new OpenIdConnectEvents
        {
            //
            // 1) LOGIN (REDIRECT PARA O CIAM)
            //
            OnRedirectToIdentityProvider = ctx =>
            {
                var http = ctx.HttpContext;

                // Lab via querystring
                var lab = http.Request.Query["lab"].ToString()?.ToLowerInvariant();
                if (string.IsNullOrWhiteSpace(lab))
                {
                    http.Response.StatusCode = 400;
                    return http.Response.WriteAsync("Erro: parâmetro 'lab' é obrigatório (ex: /auth/login?lab=lab1)");
                }

                // Guarda o lab em cookie — necessário para o callback
                http.Response.Cookies.Append("mlab_lab", lab, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Path = "/"
                });

                // Lê config do lab
                var labConfig = builder.Configuration.GetSection($"AuthenticationLabs:{lab}");
                var authority = labConfig["Authority"];
                var clientId = labConfig["ClientId"];
                var clientSecret = labConfig["ClientSecret"];

                if (string.IsNullOrEmpty(authority) || string.IsNullOrEmpty(clientId))
                {
                    http.Response.StatusCode = 400;
                    return http.Response.WriteAsync($"Erro: laboratório '{lab}' não possui configuração válida.");
                }

                // Ajuste do endpoint de autorização
                var issuer = authority.Replace("/v2.0", "/oauth2/v2.0/authorize");

                // Override dos valores reais
                ctx.ProtocolMessage.IssuerAddress = issuer;
                ctx.ProtocolMessage.ClientId = clientId;
                ctx.ProtocolMessage.SetParameter("client_secret", clientSecret);

                //
                // Forçar login SEM KMSI + tela limpa
                //
                //ctx.ProtocolMessage.Prompt = "login consent";
                //AADSTS90023: Unsupported 'prompt' value.
                ctx.ProtocolMessage.Prompt = "login";

                ctx.ProtocolMessage.SetParameter("login_hint", "");
                ctx.ProtocolMessage.SetParameter("domain_hint", "none");
                ctx.ProtocolMessage.SetParameter("max_age", "0");
                ctx.ProtocolMessage.SetParameter("remember", "false");
                ctx.ProtocolMessage.SetParameter("suppress_prompt", "true");
                ctx.ProtocolMessage.SetParameter("auth_method", "refresh_session");
                ctx.ProtocolMessage.SetParameter("disable_kmsi", "true");
                ctx.ProtocolMessage.SetParameter("disable_kmsi", "1");

                ctx.ProtocolMessage.SetParameter("ui_locales", ui);
                ctx.ProtocolMessage.SetParameter("mkt", ui);

                // Evita KMSI em form_post
                ctx.ProtocolMessage.ResponseMode = "query";

                Console.WriteLine($"🔹 Login iniciado para LAB: {lab}");

                return Task.CompletedTask;
            },

            //
            // 2) CALLBACK (TROCA DO AUTH CODE POR TOKEN)
            //
            OnAuthorizationCodeReceived = ctx =>
            {
                var http = ctx.HttpContext;

                // Recupera o lab salvo no cookie
                var lab = http.Request.Cookies["mlab_lab"]?.ToLowerInvariant();

                if (string.IsNullOrWhiteSpace(lab))
                {
                    throw new Exception("Não foi possível determinar o lab no callback.");
                }

                var labConfig = builder.Configuration.GetSection($"AuthenticationLabs:{lab}");
                var clientId = labConfig["ClientId"];
                var clientSecret = labConfig["ClientSecret"];

                // Override REAL usado no token endpoint
                ctx.TokenEndpointRequest.ClientId = clientId;
                ctx.TokenEndpointRequest.ClientSecret = clientSecret;

                Console.WriteLine($"🔹 Callback autorizado pelo LAB: {lab}");

                return Task.CompletedTask;
            },

            //
            // 3) LOGOUT
            //
            OnRedirectToIdentityProviderForSignOut = ctx =>
            {
                ctx.ProtocolMessage.SetParameter("ui_locales", ui);
                ctx.ProtocolMessage.SetParameter("mkt", ui);
                return Task.CompletedTask;
            },

            //
            // 4) TOKEN VALIDADO
            //
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

                return Task.CompletedTask;
            }
        };
    });

//
// MVC + Swagger + AI
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
// Forward headers — essencial para ngrok/containers
//
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedFor,
    RequireHeaderSymmetry = false,
    ForwardLimit = null,
    KnownNetworks = { },
    KnownProxies = { }
});

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

//
// Segurança
//
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

app.UseRateLimiter();
app.UseCors("app");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
