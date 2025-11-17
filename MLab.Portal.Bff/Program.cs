using Microsoft.IdentityModel.Logging;
using MLab.Portal.Bff.Configuration;
using MLab.Portal.Bff.Security.Cors;
using MLab.Portal.Bff.Security.Headers;
using MLab.Portal.Bff.Security.OidcAuthentication;
using MLab.Portal.Bff.Security.RateLimit;
using System.Diagnostics;

IdentityModelEventSource.ShowPII = Debugger.IsAttached;

var builder = WebApplication.CreateBuilder(args);

// ==================== CORS ====================
builder.Services.AddAppCors(builder.Configuration);

builder.Services.AddHttpContextAccessor();

// ==================== CONFIG (Frontend) ====================
builder.Services.Configure<FrontendConfig>(builder.Configuration.GetSection("Frontend"));

// ==================== DATA PROTECTION ====================
builder.Services.AddBlobDataProtection(builder.Configuration, builder.Environment);

// ==================== AUTHENTICATION ====================
builder.Services.AddOidcMultiTenantAuthentication(builder.Configuration);

// ==================== MVC & RATE LIMITING ====================
builder.Services.AddControllers();
builder.Services.AddAuthorization();
builder.Services.AddRateLimiting(builder.Configuration);

// ==================== SWAGGER ====================
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// ==================== MIDDLEWARE PIPELINE ====================
app.UseForwardedHeadersDefaults();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseSecurityHeaders();

app.UseRateLimiter();
app.UseCors("app");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
