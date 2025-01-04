using System.ComponentModel.DataAnnotations;

namespace CasinoPro.Models
{
    public class UserRole
    {
        [Key]
        [ScaffoldColumn(false)]
        public string Username { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
    }
}
