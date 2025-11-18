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

    [HttpGet("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var lab = HttpContext.Request.Cookies["mlab_lab"]?.ToLower();

        if (string.IsNullOrWhiteSpace(lab))
            return Redirect(_frontConfig.BaseUrl);

        // 1. Remove cookie local
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // 2. Logout federado no IDP (Azure Entra)
        await HttpContext.SignOutAsync(
            lab, // ← esquema correto multi-tenant
            new AuthenticationProperties
            {
                RedirectUri = "/auth/logged-out-callback"
            }
        );

        return new EmptyResult(); // Azure fará o redirect para /auth/logged-out-callback
    }

    [AllowAnonymous]
    [HttpGet("logged-out-callback")]
    public IActionResult LoggedOutCallback()
    {
        // Depois do federated logout, o usuário foi removido do IdP corretamente.
        // Agora podemos devolver a SPA.
        return Redirect($"{_frontConfig.BaseUrl}/");
    }

    [HttpPost("logout-spa")]
    [Authorize]
    public IActionResult LogoutSpa()
    {
        // Retorna ao SPA a URL para iniciar o federated logout
        var federatedUrl = $"{Request.Scheme}://{Request.Host}/auth/logout";

        return Ok(new { redirect = federatedUrl });
    }

    [HttpPost("logout-spa-only")]
    [Authorize]
    public async Task<IActionResult> LogoutSpaOnly()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Ok(new { redirect = "/" }); // volta para login direto
    }
}
