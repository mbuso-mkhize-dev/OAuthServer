using OAuthServer.ApplicationLogic.Entities;
using OAuthServer.EntityFramework.Core.Models;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace OAuthServer.ApplicationLogic.Interfaces
{
    public interface IUserService
    {
        Task<UserEntity> RegisterUserAsync(UserEntity model);

        User GetUserByEmail(string email);
        
        Task<FacebookUserEntity> RegisterFacebookUserAsync(string accessToken);

        Task UpdateFacebookAuthenticationTokensAsync(ClaimsPrincipal principal, FacebookAccessToken facebookAccessToken, string providerKey);
    }
}
