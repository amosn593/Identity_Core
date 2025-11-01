using IdentityCoreDemo.Authentication;
using IdentityCoreDemo.Database;
using IdentityCoreDemo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace IdentityCoreDemo.Features;

public class LoginUser
{
    public record UserLoginDto(string Email, string Password);

    public record UserLoginResponeDto(string? Token, string? RefreshToken);

    public static void MapEndpoint(IEndpointRouteBuilder app)
    {
        app.MapPost("/login", async (UserLoginDto userDto,
            TokenGenerator tokenGenerator,
            UserManager <ApplicationUser> userManager) =>
        {
            var user = await userManager.FindByEmailAsync(userDto.Email);

            if (user == null || !await userManager.CheckPasswordAsync(user, userDto.Password))
            {
                return Results.Unauthorized();
            }

            var Roles = await userManager.GetRolesAsync(user);

            

            var Token = tokenGenerator.Token(user, Roles);

            var Refresh = tokenGenerator.RefreshToken();

            var RefreshToken = new RefreshToken
            {
                Id = Guid.NewGuid(),
                Token = Refresh,
                ExpireUtc = DateTime.UtcNow.AddHours(1),
                UserId = user.Id
            };

            return Results.Ok(new UserLoginResponeDto(Token, Refresh));

        });

        app.MapGet("/me", (ClaimsPrincipal claims) =>
        {
            return Results.Ok(claims.Claims.ToDictionary(c => c.Type, c => c.Value));

        }).RequireAuthorization(policy => policy.RequireRole(Roles.Cashier));

    }
}
