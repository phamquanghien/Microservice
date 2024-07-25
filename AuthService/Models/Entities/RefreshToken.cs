using System.ComponentModel.DataAnnotations;

namespace AuthService.Models.Entities
{
    public class RefreshToken
    {
        [Key]
        public long RefreshTokenId { get; set; }
        public required string Token { get; set; }
        public DateTime CreatedTime { get; set; } = DateTime.UtcNow;
        public DateTime ExpiredTime { get; set; }
        public DateTime? Revoked { get; set; }
        public bool IsRevoked => Revoked != null;
        public bool IsActive => !IsExpired && !IsRevoked;
        public bool IsExpired => DateTime.UtcNow >= ExpiredTime;
        public required string UserId { get; set; }
        public ApplicationUser User { get; set; }
    }
}