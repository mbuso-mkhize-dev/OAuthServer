using System;
using System.Collections.Generic;
using System.Text;

namespace OAuthServer.ApplicationLogic.Entities
{
    public class JwtSettingsEntity
    {
        public string Secret { get; set; }

        public TimeSpan TokenLifetime { get; set; }

        public string Issuer { get; set; }

        public int TokenLifeTimeInSecs { get; set; }


        public int RefreshTokenLifeTimeInSecs { get; set; }
    }
}
