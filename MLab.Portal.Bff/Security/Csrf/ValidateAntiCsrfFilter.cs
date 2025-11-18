//using Microsoft.AspNetCore.Mvc;
//using Microsoft.AspNetCore.Mvc.Filters;
//using Microsoft.AspNetCore.Authorization;

//namespace MLab.Portal.Bff.Security.Csrf;

///// <summary>
///// Filtro global para validar CSRF apenas em actions com [Authorize] e verbos sensíveis.
///// </summary>
//public class ValidateAntiCsrfFilter : IAuthorizationFilter
//{
//    private readonly ILogger<ValidateAntiCsrfFilter> _logger;

//    public ValidateAntiCsrfFilter(ILogger<ValidateAntiCsrfFilter> logger)
//    {
//        _logger = logger;
//    }

//    public void OnAuthorization(AuthorizationFilterContext context)
//    {
//        var http = context.HttpContext;
//        var request = http.Request;

//        // Só verifica se o usuário estiver autenticado
//        if (!http.User.Identity?.IsAuthenticated ?? true)
//            return;

//        // Apenas métodos que modificam estado
//        if (request.Method != HttpMethods.Post &&
//            request.Method != HttpMethods.Put &&
//            request.Method != HttpMethods.Delete)
//            return;

//        // Checa se o endpoint tem [AllowAnonymous]
//        var endpoint = context.ActionDescriptor.EndpointMetadata;
//        if (endpoint.OfType<AllowAnonymousAttribute>().Any())
//            return;

//        // Faz a verificação do cookie duplo
//        var tokenHeader = request.Headers["X-XSRF-TOKEN"].FirstOrDefault();
//        var tokenCookie = request.Cookies["XSRF-TOKEN"];

//        if (string.IsNullOrEmpty(tokenHeader) ||
//            string.IsNullOrEmpty(tokenCookie) ||
//            tokenHeader != tokenCookie)
//        {
//            _logger.LogWarning("CSRF token inválido em {Path}", request.Path);
//            context.Result = new UnauthorizedObjectResult(new
//            {
//                error = "CSRF token inválido"
//            });
//        }
//    }
//}
