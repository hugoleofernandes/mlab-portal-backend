using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace PortalCliBackend.Controllers;

[ApiController]
[Route("session")]
public class SessionController : ControllerBase
{
    [HttpGet("me")]
    [Authorize]
    public IActionResult Me()
    {
        var user = new
        {
            name = User.Identity?.Name,
            email = User.FindFirst("preferred_username")?.Value
                ?? User.FindFirst(ClaimTypes.Email)?.Value,
            sub = User.FindFirst("sub")?.Value
        };

        return Ok(user);
    }

    [HttpGet("debug")]
    [Authorize]
    public IActionResult DebugSession([FromServices] IWebHostEnvironment env)
    {
        if (!env.IsDevelopment()) return NotFound();

        var claims = User.Claims.Select(c => new { c.Type, c.Value });
        return Ok(new { user = User.Identity?.Name, claims });
    }
}
