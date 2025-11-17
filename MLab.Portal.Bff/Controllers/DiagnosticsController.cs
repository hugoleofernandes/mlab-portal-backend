using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MLab.Portal.Bff.Controllers;

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
        return Ok(new { ok = true, environment = _env.EnvironmentName, at = DateTime.UtcNow, v = "2" });
    }

    [HttpGet("env")]
    public IActionResult GetEnvironmentVariables()
    {
        if (!_env.IsDevelopment())
            return Unauthorized(new { error = "Not available in non-DEV environments." });

        // Captura todas as variáveis de ambiente disponíveis
        var envVars = Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(entry => (string)entry.Key!, entry => (string?)entry.Value);

        // Filtra apenas as relevantes da aplicação
        var filtered = envVars
            //.Where(kv => kv.Key.StartsWith("Authentication__") || kv.Key.StartsWith("Cors__"))
            .OrderBy(kv => kv.Key)
            .ToDictionary(kv => kv.Key, kv => kv.Value);

        return Ok(new
        {
            environment = _env.EnvironmentName,
            hostname = Environment.MachineName,
            variables = filtered
        });
    }
}
