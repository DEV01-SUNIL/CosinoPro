using System.ComponentModel.DataAnnotations;

namespace CasinoPro.Models
{
    public class VMRegister
    {
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
