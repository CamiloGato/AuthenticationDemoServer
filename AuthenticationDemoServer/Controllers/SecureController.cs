using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationDemoServer.Controllers;

[ApiController]
[Route("[controller]")]
public class SecureController : ControllerBase
{
    [HttpGet("admin")]
    [Authorize(Policy = "AdminPolicy")]
    public IActionResult AdminEndpoint()
    {
        return Ok("Welcome, Admin! This is a secure admin-only endpoint.");
    }

    [HttpGet("user")]
    [Authorize(Policy = "UserPolicy")]
    public IActionResult UserEndpoint()
    {
        return Ok("Hello, User! This is a secure user-only endpoint.");
    }
}