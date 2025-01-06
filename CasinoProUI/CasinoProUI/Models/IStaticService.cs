using CasinoPro.Models;
using CasinoProUI.Services;

namespace CasinoProUI.Models
{
    public interface IStaticService
    {
        T GetSessionValue<T>(string key);

        ResJsonOutput VerifyUser(VMLogin loginmodel);

        Task<ResJsonOutput> PostDataAsync(string ApiPath, object obj, List<KeyValue> Headers = null);

        VMRegister GetLoginUser();
    }
}
