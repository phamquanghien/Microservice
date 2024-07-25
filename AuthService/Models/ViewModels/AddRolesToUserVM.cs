namespace AuthService.Models.ViewModels
{
    public class AddRolesToUserVM
    {
        public required string UserId { get; set; }
        public List<string>? RoleNames { get; set; }
    }
}