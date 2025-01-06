using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CasinoProUI.Services
{
    public static class SessionExtensionMethods
    {
        public static void SetObject(this ISession session,
                      string key, object value)
        {
            string stringValue = JsonConvert.
                                 SerializeObject(value);
            session.SetString(key, stringValue);
        }

        public static T GetObject<T>(this ISession session,
                                     string key)
        {
            T value = default(T);
            string stringValue = session.GetString(key);
            if (stringValue != null)
                value = JsonConvert.DeserializeObject<T>
                                      (stringValue);
            return value;
        }

    }
}
