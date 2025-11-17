using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using MLab.Portal.Bff.Configuration;

namespace MLab.Portal.Bff.Controllers;

/// <summary>
/// Responsible for initiating login and logout flows through the BFF.
/// The frontend never interacts directly with the identity provider — only with this controller.
/// 
/// This design allows the BFF to:
/// - control the RedirectUri sent to the Hosted UI,
/// - manage session cookies securely,
/// - avoid exposing client secrets to the frontend,
/// - implement multi-tenant authentication based on the selected lab.
/// 
/// The BFF acts as the security boundary between the frontend and the identity system.
/// </summary>


[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly FrontendConfig _frontConfig;

    public AuthController(ILogger<AuthController> logger, IOptions<FrontendConfig> frontOptions)
    {
        _logger = logger;
        _frontConfig = frontOptions.Value;
    }

    [HttpGet("login")]
    public IActionResult Login(string lab, [FromServices] IConfiguration config)
    {
        var labs = config.GetSection("AuthenticationLabs").GetChildren().Select(c => c.Key);

        if (!labs.Contains(lab))
            return BadRequest("lab inválido");

        string home = $"{_frontConfig.BaseUrl}/app/home";

        var props = new AuthenticationProperties
        {
            RedirectUri = home
        };

        return Challenge(props, lab);
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var user = HttpContext.User.Identity?.Name ?? "Desconhecido";
        _logger.LogInformation("Logout iniciado por {User} às {Time}", user, DateTimeOffset.UtcNow);

        //await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        //await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme,
        //    new AuthenticationProperties { RedirectUri = "https://localhost:5173/" });

        return SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            CookieAuthenticationDefaults.AuthenticationScheme
        // opcionalmente também "lab1"/"lab2" se quiser federated signout
        );

        //_logger.LogInformation("Logout completo para {User}", user);
        //return Ok(new { message = "Logout completo e protegido" });
    }
}
