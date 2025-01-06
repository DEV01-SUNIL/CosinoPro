using System.ComponentModel;


namespace CasinoPro.Models
{
    public class TokenData
    {
        [DisplayName("AccessToken")]
        public string Token { get; set; } = string.Empty;

        [DisplayName("Expiry")]
        public long Expiry { get; set; } = 0;
    }

}
