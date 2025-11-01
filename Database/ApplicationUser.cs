using Microsoft.AspNetCore.Identity;

namespace IdentityCoreDemo.Database;

public sealed class ApplicationUser : IdentityUser
{
    public string? Initials { get; set; }
}
