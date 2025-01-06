using System.ComponentModel.DataAnnotations;

namespace CasinoPro.Models
{
    public class Login
    {
        [Key]
        [ScaffoldColumn(false)]
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
