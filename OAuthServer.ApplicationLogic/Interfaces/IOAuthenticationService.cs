using OAuthServer.ApplicationLogic.Entities;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace OAuthServer.ApplicationLogic.Interfaces
{
    public interface IOAuthenticationService
    {
        Task<AuthenticationResult> AuthenticateUserAsync(UserEntity userEntity);

        Task<AuthenticationResult> AuthenticateUserFromRefreshToken(string token);
    }
}
