using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace PortalCliBackend.Controllers;

[ApiController]
[Route("api/diagnostics")]
public class DiagnosticsController : ControllerBase
{
    private readonly IWebHostEnvironment _env;

    public DiagnosticsController(IWebHostEnvironment env)
    {
        _env = env;
    }

    [HttpGet("debug")]
    [Authorize]
    public IActionResult Debug()
    {
        if (!_env.IsDevelopment())
            return Forbid("Endpoint disponível apenas em ambiente de desenvolvimento.");

        var claims = User.Claims.Select(c => new { c.Type, c.Value });
        return Ok(claims);
    }

    [HttpGet("ping")]
    public IActionResult Ping()
    {
        return Ok(new { ok = true, environment = _env.EnvironmentName, at = DateTime.UtcNow });
    }
}
