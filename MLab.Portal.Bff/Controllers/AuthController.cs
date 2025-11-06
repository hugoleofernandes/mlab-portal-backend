using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace PortalCli.Api.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;

    public AuthController(ILogger<AuthController> logger)
    {
        _logger = logger;
    }

    [HttpGet("login")]
    public async Task<IActionResult> Login()
    {
        var props = new AuthenticationProperties { RedirectUri = "/" };
        await HttpContext.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, props);
        
        return new EmptyResult();
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var user = HttpContext.User.Identity?.Name ?? "Desconhecido";
        _logger.LogInformation("Logout iniciado por {User} às {Time}", user, DateTimeOffset.UtcNow);

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme,
            new AuthenticationProperties { RedirectUri = "https://localhost:5173/" });

        _logger.LogInformation("Logout completo para {User}", user);
        return Ok(new { message = "Logout completo e protegido" });
    }
}
