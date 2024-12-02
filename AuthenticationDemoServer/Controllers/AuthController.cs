using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationDemoServer.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly List<User> _users = new()
    {
        new User { Username = "admin", Password = "adminpass", Role = "Admin" },
        new User { Username = "user", Password = "userpass", Role = "User" }
    };

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var user = _users.FirstOrDefault(u =>
            u.Username == request.Username && u.Password == request.Password);

        if (user == null)
        {
            return Unauthorized("Invalid credentials");
        }

        var token = GenerateJwtToken(user);
        return Ok(new { Token = token });
    }

    private string GenerateJwtToken(User user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        };

        var key = new SymmetricSecurityKey("MyVerySecureSuperSecretKey12345!"u8.ToArray());
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: "SimpleAuthDemo",
            audience: "SimpleAuthDemo",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

public class LoginRequest
{
    public string? Username { get; set; }
    public string? Password { get; set; }
}

public class User
{
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? Role { get; set; }
}