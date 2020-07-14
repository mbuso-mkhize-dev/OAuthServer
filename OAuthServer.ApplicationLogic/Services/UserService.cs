using Microsoft.AspNetCore.Identity;
using OAuthServer.ApplicationLogic.Entities;
using OAuthServer.ApplicationLogic.Interfaces;
using OAuthServer.EntityFramework.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace OAuthServer.ApplicationLogic.Services
{
    public class UserService : IUserService
    {
        private readonly IBaseRepository<User> _userRepository;
        private readonly UserManager<User> _userManager;
        public UserService(IBaseRepository<User> userRepository, UserManager<User> userManager)
        {
            _userRepository = userRepository;
            _userManager = userManager;
        }
        public User GetUserByEmail(string email)
        {
            return _userRepository.Where(c => c.Email == email).FirstOrDefault();
        }
        public async Task<UserEntity> RegisterUserAsync(UserEntity model)
        {
            //_userRepository.Add(new User
            //{
            //    Email = model.Email,
            //    FirstName = model.Name,
            //    UserName = model.Email
            //});

            //await _userRepository.SaveAsync();

            var identityResult = await _userManager.CreateAsync(new User
            {
                Email = model.Email,
                FirstName = model.Name,
                UserName = model.Email
            }, model.Password);


            if(!identityResult.Succeeded)
            {
                throw new Exception("User registration.");
            }

            return model;
        }

        public Task<FacebookUserEntity> RegisterFacebookUserAsync(string accessToken)
        {
            throw new NotImplementedException();
        }

        public Task UpdateFacebookAuthenticationTokensAsync(ClaimsPrincipal principal, FacebookAccessToken facebookAccessToken, string providerKey)
        {
            throw new NotImplementedException();
        }
    }
}
