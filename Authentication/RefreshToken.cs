using System.ComponentModel.DataAnnotations;

namespace IdentityCoreDemo.Authentication;

public class RefreshToken
{
    [Key]
    public Guid Id { get; set; }
    public string Token { get; set; }
    public DateTime ExpireUtc { get; set; }
    public string UserId { get; set; }

}
