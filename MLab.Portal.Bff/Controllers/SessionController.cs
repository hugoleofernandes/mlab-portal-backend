using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace MLab.Portal.Bff.Controllers;

/// <summary>
/// Exposes session-related endpoints for the BFF. These endpoints allow the frontend
/// to retrieve authenticated user data (/session/me) and debug claims during development
/// (/session/debug).
/// 
/// This controller is the main integration point for the frontend to verify whether 
/// the authentication cookie is valid and establish the user's logged-in state.
/// </summary>


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
