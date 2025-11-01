using IdentityCoreDemo.Database;
using IdentityCoreDemo.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityCoreDemo.Features;

public static class RegisterUser
{
    public record CreateUserDto(string Email, string Initials, string Password);

    public static void MapEndpoint(IEndpointRouteBuilder app)
    {
        app.MapPost("/register", async (CreateUserDto createrUser, ApplicationDbContext dbContext, UserManager<ApplicationUser> userManager) =>
        {
            using var transaction = await dbContext.Database.BeginTransactionAsync();
            var user = new ApplicationUser
            {
                Email = createrUser.Email,
                Initials = createrUser.Initials,
                UserName = createrUser.Email
            };

            var identity = await userManager.CreateAsync(user, createrUser.Password);

            if (!identity.Succeeded)
            {
                return Results.BadRequest(identity.Errors);
            }

            var IdentityR = await userManager.AddToRoleAsync(user, Roles.Member);

            if (!IdentityR.Succeeded)
            {
                return Results.BadRequest(identity.Errors);
            }

            await transaction.CommitAsync();

            return Results.Ok(user);

        });
    }
}
