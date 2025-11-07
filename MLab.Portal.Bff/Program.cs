using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using MLab.Portal.Bff.Security.Csrf;
using System.Security.Claims;
using System.Threading.RateLimiting;



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
// Autenticação & Cookie Seguro
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
        options.Cookie.SameSite = SameSiteMode.None; // necessário para CORS com front separado
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    })
    .AddOpenIdConnect(options =>
    {
        var cfg = builder.Configuration.GetSection("Authentication");

        options.Authority = cfg["Authority"]; // Ex: https://tenant.ciamlogin.com/{domain}/v2.0
        options.ClientId = cfg["ClientId"];
        options.ClientSecret = cfg["ClientSecret"];
        options.ResponseType = OpenIdConnectResponseType.Code; // PKCE
        options.UsePkce = true;

        options.CallbackPath = cfg["CallbackPath"];                 // /signin-oidc
        options.SignedOutCallbackPath = cfg["SignedOutCallbackPath"]; // /signout-callback-oidc

        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = false; // tokens não são persistidos no cookie

        // Escopos padrão
        options.Scope.Clear();
        foreach (var s in (cfg["Scopes"] ?? "openid profile email").Split(' ', StringSplitOptions.RemoveEmptyEntries))
            options.Scope.Add(s);

        // Validação
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;

        // Eventos personalizados (idioma e logout)
        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = ctx =>
            {
                var ui = cfg["UiLocales"] ?? "pt-BR";
                ctx.ProtocolMessage.SetParameter("ui_locales", "pt-BR");
                ctx.ProtocolMessage.Prompt = "login"; // força reautenticação
                return Task.CompletedTask;
            },
            OnRedirectToIdentityProviderForSignOut = ctx =>
            {
                var ui = cfg["UiLocales"] ?? "pt-BR";
                ctx.ProtocolMessage.SetParameter("ui_locales", "pt-BR");
                return Task.CompletedTask;
            },
            OnTokenValidated = ctx =>
            {
                var http = ctx.HttpContext;

                // Gera token XSRF assim que login é validado
                var xsrfToken = Guid.NewGuid().ToString("N");

                http.Response.Cookies.Append("XSRF-TOKEN", xsrfToken, new CookieOptions
                {
                    HttpOnly = false, // JS pode ler
                    Secure = true, // Apenas HTTPS
                    SameSite = SameSiteMode.None,
                    Path = "/" // disponível para todo o app
                });

                // Log 
                var user = ctx.Principal?.Identity?.Name ?? "Desconhecido";
                var logger = http.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("Login");
                logger.LogInformation("Token XSRF criado para {User} em {Time}", user, DateTimeOffset.UtcNow);

                return Task.CompletedTask;
            }
        };
    });

//
// Autorização + MVC + Swagger + Insigths
//
builder.Services.AddAuthorization();

//builder.Services.AddControllers();

builder.Services.AddControllers(options =>
{
    // Adiciona o filtro global de CSRF
    options.Filters.Add<ValidateAntiCsrfFilter>();
});

//
// Rate Limiting - impede flood/brute force
//
builder.Services.AddRateLimiter(_ => _
    .AddFixedWindowLimiter("default", options =>
    {
        options.PermitLimit = 30;               // 30 requisições
        options.Window = TimeSpan.FromMinutes(1); // por minuto
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        options.QueueLimit = 5; // fila curta
    })
);



builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddApplicationInsightsTelemetry();

var app = builder.Build();



//
// Pipeline de execução
//
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();


// === Segurança Avançada ===

//Clickjacking	X-Frame-Options: DENY Impede que alguém embede seu site em um <iframe> malicioso.
//MIME sniffing	X-Content-Type-Options: nosniff Bloqueia execução de scripts com MIME incorreto.
//Referer leakage	Referrer-Policy: strict - origin - when - cross - origin    Evita enviar URLs completas para outros sites.
//XSS básico	X-XSS-Protection	Ativa filtro básico em browsers legados.
//Content Security Policy (CSP)	Content-Security-Policy: ...	Principal barreira contra XSS moderno.
//Cache-Control	no-store etc.	Impede caching de respostas sensíveis.
//HSTS	UseHsts()	Força HTTPS sempre (com preload possível).
//Rate Limiter	AddRateLimiter()	Limita requisições por IP, bloqueia flood/abuso.



// Segurança de cabeçalhos HTTP
app.Use((context, next) =>
{
    var headers = context.Response.Headers;

    headers["X-Frame-Options"] = "DENY"; // bloqueia embedding em iframes
    headers["X-Content-Type-Options"] = "nosniff"; // bloqueia MIME sniffing
    headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    headers["X-XSS-Protection"] = "1; mode=block"; // ainda útil em alguns browsers

    // Content Security Policy (CSP)
    headers["Content-Security-Policy"] =
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: https://*.microsoft.com; " +
        "frame-ancestors 'none'; " +
        "object-src 'none'; " +
        "base-uri 'self';";

    // Cache policy
    headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    headers["Pragma"] = "no-cache";
    headers["Expires"] = "0";

    return next();
});

// Força HTTPS + Rate Limiting
if (!app.Environment.IsDevelopment())
{
    app.UseHsts(); // ativa Strict-Transport-Security em prod
}
app.UseRateLimiter();
// ==========================



app.UseCors("app");
app.UseAuthentication();
app.UseAuthorization();

// Controllers (Auth, Session, etc.)
app.MapControllers();

app.Run();
