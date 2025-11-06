using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// CORS para o SvelteKit
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
builder.Services.AddCors(opt =>
{
    opt.AddPolicy("app", p => p
        .WithOrigins(allowedOrigins)
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials());
});

// Cookie seguro
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = ".mlab.portal.session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None; // necessário p/ front em outro domínio
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
})
.AddOpenIdConnect(options =>
{
    var cfg = builder.Configuration.GetSection("Authentication");
    options.Authority = cfg["Authority"]; // https://{tenant}.ciamlogin.com/{domain}/v2.0
    options.ClientId = cfg["ClientId"];
    options.ClientSecret = cfg["ClientSecret"];
    options.ResponseType = OpenIdConnectResponseType.Code; // Authorization Code + PKCE
    options.UsePkce = true;

    options.CallbackPath = cfg["CallbackPath"];                 // /signin-oidc
    options.SignedOutCallbackPath = cfg["SignedOutCallbackPath"]; // /signout-callback-oidc

    options.GetClaimsFromUserInfoEndpoint = true;
    options.SaveTokens = false; // tokens não vão para cookie
    options.Scope.Clear();
    foreach (var s in (cfg["Scopes"] ?? "openid profile email").Split(' ', StringSplitOptions.RemoveEmptyEntries))
        options.Scope.Add(s);

    // Validação de token
    options.TokenValidationParameters.NameClaimType = "name";
    options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;

    // Idioma PT-BR no Hosted UI (quando suportado)
    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = ctx =>
        {
            var ui = cfg["UiLocales"] ?? "pt-BR";
            ctx.ProtocolMessage.SetParameter("ui_locales", ui);
            // Opcional: Prompt para evitar lista de contas (ou "select_account")
            // ctx.ProtocolMessage.Prompt = "login";
            return Task.CompletedTask;
        },
        // Ajusta SameSite em cenários de IFrame/3rd-party se necessário
        OnRedirectToIdentityProviderForSignOut = ctx =>
        {
            var ui = cfg["UiLocales"] ?? "pt-BR";
            ctx.ProtocolMessage.SetParameter("ui_locales", ui);
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();

// Swagger Configuration
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
//

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    // Swagger Configuration
    app.UseSwagger();
    app.UseSwaggerUI();
    //
}

app.UseHttpsRedirection();
app.UseCors("app");
app.UseAuthentication();
app.UseAuthorization();

// ---- Endpoints BFF ----

// 1) Iniciar login (redireciona para Entra)
app.MapGet("/auth/login", async (HttpContext http) =>
{
    var props = new AuthenticationProperties
    {
        RedirectUri = "/" // para onde voltar depois do login
    };
    await http.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, props);
    return Results.Empty;
});

// 2) Logout (encerra cookie + SLO no Entra)
app.MapPost("/auth/logout", async (HttpContext http) =>
{
    await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await http.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme,
        new AuthenticationProperties {
            RedirectUri = "https://localhost:5173/" // depois troca pro front real
        });
    return Results.Ok();
});

// 3) Sessão atual (para o SvelteKit exibir usuário logado)
app.MapGet("/session/me", (HttpContext http) =>
{
    if (!http.User.Identity?.IsAuthenticated ?? true)
        return Results.Unauthorized();

    var user = new
    {
        name = http.User.Identity!.Name,
        email = http.User.FindFirst("preferred_username")?.Value
                ?? http.User.FindFirst(ClaimTypes.Email)?.Value,
        sub = http.User.FindFirst("sub")?.Value
    };
    return Results.Ok(user);
});

// 4) Exemplo de rota protegida
app.MapGet("/api/secure/ping", () => Results.Ok(new { ok = true, at = DateTimeOffset.UtcNow }))
   .RequireAuthorization();

app.MapControllers();

app.Run();
