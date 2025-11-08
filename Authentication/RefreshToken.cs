using IdentityCoreDemo.Database;
using System.ComponentModel.DataAnnotations;

namespace IdentityCoreDemo.Authentication;

public class RefreshToken
{
    [Key]
    public Guid Id { get; set; }
    public string Token { get; set; } = string.Empty;
    public DateTime ExpireUtc { get; set; }
    public string UserId { get; set; } = string.Empty;
    public  ApplicationUser User { get; set; }

}
