using Microsoft.Extensions.DependencyInjection;
using OAuthServer.ApplicationLogic.Interfaces;
using OAuthServer.ApplicationLogic.Services;
using OAuthServer.EntityFramework.Core.Models;
using OAuthServer.EntityFramework.Repository;

namespace OAuthServer.DI
{
    public static class ServiceCollectionBuilder
    {
        public static void AddServices(IServiceCollection services)
        {
            // Business Logic
            services.AddScoped<IUserService, UserService>();
            services.AddScoped<IOAuthenticationService, OAuthenticationService>();

            // Repositories
            services.AddScoped<IBaseRepository<User>, BaseRepository<User>>();
        }
    }
}