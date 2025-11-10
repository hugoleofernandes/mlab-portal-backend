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

    [HttpGet("ping")]
    public IActionResult Ping()
    {
        return Ok(new { ok = true, environment = _env.EnvironmentName, at = DateTime.UtcNow, v = "1" });
    }
}
