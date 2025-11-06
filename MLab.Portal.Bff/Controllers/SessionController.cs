using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace PortalCliBackend.Controllers;

[ApiController]
[Route("session")]
public class SessionController : ControllerBase
{
    [HttpGet("me")]
    public IActionResult GetSession()
    {
        if (!User.Identity?.IsAuthenticated ?? true)
            return Unauthorized();

        var user = new
        {
            name = User.Identity?.Name,
            email = User.FindFirst("preferred_username")?.Value
                    ?? User.FindFirst(ClaimTypes.Email)?.Value,
            sub = User.FindFirst("sub")?.Value
        };

        return Ok(user);
    }
}
