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
    public async Task<IActionResult> Login(string lab)
    {
        if (lab != "lab1" && lab != "lab2")
            return BadRequest("lab inválido");
        
        return Challenge(new AuthenticationProperties { RedirectUri = "/" }, lab); // <- aqui é exatamente o nome do scheme


        //var props = new AuthenticationProperties { RedirectUri = "/" };
        //await HttpContext.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, props);


        //return new EmptyResult();
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

        _logger.LogInformation("Logout completo para {User}", user);
        return Ok(new { message = "Logout completo e protegido" });
    }
}
