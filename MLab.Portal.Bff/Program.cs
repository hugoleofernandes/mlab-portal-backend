using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

//
// 1. Configuração de CORS
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
// 2. Autenticação & Cookie Seguro
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
                ctx.ProtocolMessage.SetParameter("ui_locales", ui);
                ctx.ProtocolMessage.Prompt = "login"; // força reautenticação
                return Task.CompletedTask;
            },
            OnRedirectToIdentityProviderForSignOut = ctx =>
            {
                var ui = cfg["UiLocales"] ?? "pt-BR";
                ctx.ProtocolMessage.SetParameter("ui_locales", ui);
                return Task.CompletedTask;
            }
        };
    });

//
// 3. Autorização + MVC + Swagger
//
builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

//
// 4. Pipeline de execução
//
//if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("app");
app.UseAuthentication();
app.UseAuthorization();

// 5. Rotas globais
//

// Health check / Diagnóstico (sempre disponível)
//app.MapGet("/api/diagnostics/ping", (IWebHostEnvironment env) =>
//{
//    return Results.Ok(new
//    {
//        ok = true,
//        environment = env.EnvironmentName,
//        at = DateTimeOffset.UtcNow
//    });
//});

// Controllers (Auth, Session, etc.)
app.MapControllers();

app.Run();
