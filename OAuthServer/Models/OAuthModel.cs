using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthServer.Models
{
    public class OAuthModel
    {
        public string GrantType { get; set; }

        public string RefreshToken { get; set; }
    }
}
