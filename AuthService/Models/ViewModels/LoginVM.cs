using System.ComponentModel.DataAnnotations;

namespace AuthService.Models.ViewModels
{
    public class LoginVM
    {
        [Required]
        [EmailAddress]
        public required string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public required string Password { get; set; }
        public bool RememberMe { get; set; }
    }
}