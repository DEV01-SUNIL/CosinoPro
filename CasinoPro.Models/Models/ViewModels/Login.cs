using System.ComponentModel.DataAnnotations;

namespace CasinoPro.Models
{
    public class VMLogin
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
