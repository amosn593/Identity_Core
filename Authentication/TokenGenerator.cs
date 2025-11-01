using IdentityCoreDemo.Database;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace IdentityCoreDemo.Authentication;

public class TokenGenerator
{
    private readonly IConfiguration _configuration;

    public TokenGenerator(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    public string? Token(ApplicationUser user, IList<string>? Roles)
    {
        //get key
        var signingkey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]!));

        //Get Creditials
        var creditials = new SigningCredentials(signingkey, algorithm: SecurityAlgorithms.HmacSha256);

        List<Claim> claims =
            [
            new(JwtRegisteredClaimNames.Sub, user.Id),
                new(JwtRegisteredClaimNames.Email, user.Email!),
                ..Roles.Select(r => new Claim(ClaimTypes.Role, r))

            ];

        //Token Descriptor
        var TokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_configuration.GetValue<int>("JWT:ExpirationInMinutes")),
            SigningCredentials = creditials,
            Issuer = _configuration["JWT:Issuer"]!,
            Audience = _configuration["JWT:Audience"]!,

        };

        //Token Handler
        var tokenHandler = new JsonWebTokenHandler();

        //Access Token
        var accessToken = tokenHandler.CreateToken(TokenDescriptor);

        return accessToken;
    }

    public string RefreshToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }
}
