using System.ComponentModel.DataAnnotations;

namespace CasinoPro.Models
{
    public class VMUserRole
    {
        public string Username { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
    }
}
