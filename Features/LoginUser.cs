using IdentityCoreDemo.Authentication;
using IdentityCoreDemo.Database;
using IdentityCoreDemo.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityCoreDemo.Features;

public class LoginUser
{
    public record UserLoginDto(string Email, string Password);

    public record UserLoginResponeDto(string? Token, string? RefreshToken);

    public static void MapEndpoint(IEndpointRouteBuilder app)
    {
        app.MapPost("/login", async (UserLoginDto userDto,
            TokenGenerator tokenGenerator,
            UserManager<ApplicationUser> userManager) =>
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

        }).RequireAuthorization(policy => policy.RequireRole(Roles.Member));

        //Google Login
        app.MapGet("/login-google", async ([FromQuery] string returnUrl, LinkGenerator linkGenerator,
            SignInManager<ApplicationUser> signInManager, HttpContext context) =>
        {
            
            var redirectUrl = linkGenerator.GetPathByName(context, "CallBackUrlGoogle") + $"?redirectUrl={returnUrl}";

            var properties = signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            
            return Results.Challenge(properties, ["Google"]);

        });

        app.MapGet("/signin-google-callback", async ([FromQuery] string redirectUrl, TokenGenerator tokenGenerator,
            UserManager<ApplicationUser> userManager, HttpContext context) =>
        {
            var result = await context.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                return Results.Unauthorized();
            }

            var email = result.Principal.FindFirst(c => c.Type == ClaimTypes.Email)?.Value;
            var name = result.Principal.Identity?.Name ?? email;

            var user = await userManager.FindByEmailAsync(email!);

            if (user == null)
            {
                //Create User and Assign default Role
                var Newuser = new ApplicationUser
                {
                    Email = email,
                    Initials = "   ",
                    UserName = email,
                    EmailConfirmed = true,
                };
                var identity = await userManager.CreateAsync(Newuser);

                if (!identity.Succeeded)
                {
                    return Results.BadRequest(identity.Errors);
                }

                var IdentityR = await userManager.AddToRoleAsync(Newuser, Roles.Member);

                if (!IdentityR.Succeeded)
                {
                    return Results.BadRequest(identity.Errors);
                }

                user = await userManager.FindByEmailAsync(email!);
            }

            var LoginInfo = new UserLoginInfo("Google", email!, "Google");

            // Check if the user already has this login
            var userLogins = await userManager.GetLoginsAsync(user!);
            var existingLogin = userLogins.FirstOrDefault(l =>
                l.LoginProvider == LoginInfo.LoginProvider &&
                l.ProviderKey == LoginInfo.ProviderKey);

            if (existingLogin == null)
            {
                var resultLogins = await userManager.AddLoginAsync(user!, LoginInfo);
                if (!resultLogins.Succeeded)
                {
                    // Handle errors
                    throw new Exception(string.Join(", ", resultLogins.Errors.Select(e => e.Description)));
                }
            }

            var RolesUsr = await userManager.GetRolesAsync(user!);

            var Token = tokenGenerator.Token(user!, RolesUsr);

            var Refresh = tokenGenerator.RefreshToken();

            var RefreshToken = new RefreshToken
            {
                Id = Guid.NewGuid(),
                Token = Refresh,
                ExpireUtc = DateTime.UtcNow.AddHours(1),
                UserId = user!.Id
            };

            var NewredirectUrl = $"{redirectUrl}/?token={Token}&refresh={Refresh}";

            return Results.Redirect(NewredirectUrl);

        }).WithName("CallBackUrlGoogle");

    }
}
