using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Transactions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using NHibernate.AspNetCore.Identity.Tests.Models;
using NHibernate.Linq;
using Xunit;

namespace NHibernate.AspNetCore.Identity.Tests
{
    public class UserStoreTest : IDisposable
    {
        private readonly ISession _session;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UpperInvariantLookupNormalizer _normalizer = new UpperInvariantLookupNormalizer();
        
        public UserStoreTest()
        {
            var factory = SessionFactoryProvider.Instance.SessionFactory;
            this._session = factory.OpenSession();
            SessionFactoryProvider.Instance.BuildSchema();
            var serviceProviderMock = new Mock<IServiceProvider>();

            var loggerFactory = new LoggerFactory();
            this._userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this._session),
                new OptionsManager<IdentityOptions>(new OptionsFactory<IdentityOptions>(new IConfigureOptions<IdentityOptions>[0], new IPostConfigureOptions<IdentityOptions>[0])),
                new PasswordHasher<ApplicationUser>(new OptionsManager<PasswordHasherOptions>(new OptionsFactory<PasswordHasherOptions>(new IConfigureOptions<PasswordHasherOptions>[0], new IPostConfigureOptions<PasswordHasherOptions>[0]))),
                new IUserValidator<ApplicationUser>[0],
                new IPasswordValidator<ApplicationUser>[0],
                this._normalizer,
                new IdentityErrorDescriber(),
                serviceProviderMock.Object,
                new Logger<UserManager<ApplicationUser>>(loggerFactory));
            this._roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(this._session),
                new IRoleValidator<IdentityRole>[0],
                this._normalizer,
                new IdentityErrorDescriber(),
                new Logger<RoleManager<IdentityRole>>(loggerFactory));
        }

        [Fact]
        public async Task WhenHaveNoUser()
        {
            var store = new UserStore<IdentityUser>(this._session);
            var user = await store.FindByLoginAsync("ProviderTest", "ProviderKey");

            Assert.Null(user);
        }

        [Fact]
        public async Task WhenAddLoginAsync()
        {
            var user = new IdentityUser("Lukz");
            var login = new UserLoginInfo("ProviderTest02", "ProviderKey02", "ProviderTest02");
            var store = new UserStore<IdentityUser>(this._session);
            using (var ts = new TransactionScope(TransactionScopeOption.RequiresNew))
            {
                await store.AddLoginAsync(user, login);
                ts.Complete();
            }

            var actual = await this._session.Query<IdentityUser>().FirstOrDefaultAsync(x => x.UserName == user.UserName);
            var userStored = await store.FindByLoginAsync(login.LoginProvider, login.ProviderKey);

            Assert.NotNull(actual);
            Assert.Equal(user.UserName, actual.UserName);
            Assert.Equal(user.UserName, userStored.UserName);
        }

        [Fact]
        public async Task WhenRemoveLoginAsync()
        {
            var user = new IdentityUser("Lukz 03");
            var login = new UserLoginInfo("ProviderTest03", "ProviderKey03", "ProviderTest03");
            var store = new UserStore<IdentityUser>(this._session);
            await store.AddLoginAsync(user, login);

            Assert.True(user.Logins.Any());

            using (var ts = new TransactionScope(TransactionScopeOption.RequiresNew))
            {
                await store.RemoveLoginAsync(user, login.LoginProvider, login.ProviderKey);
                ts.Complete();
            }

            var actual = await this._session.Query<IdentityUser>().FirstOrDefaultAsync(x => x.UserName == user.UserName);
            Assert.False(actual.Logins.Any());
        }

        [Fact]
        public async Task WhenCreateUserAsync()
        {
            var user = new ApplicationUser { UserName = "RealUserName" };

            using (var transaction = new TransactionScope())
            {
                var result = await this._userManager.CreateAsync(user, "RealPassword");
                transaction.Complete();
                Assert.Empty(result.Errors);
            }

            var actual = await this._session.Query<ApplicationUser>().FirstOrDefaultAsync(x => x.UserName == user.UserName);

            Assert.NotNull(actual);
            Assert.Equal(user.UserName, actual.UserName);
        }

        [Fact]
        public async Task GivenHaveRoles_WhenDeleteUser_ThenDeletingCausesNoCascade()
        {
            var user = new IdentityUser("Lukz 04");
            var role = new IdentityRole("ADM") { NormalizedName = "ADM" };
            var store = new UserStore<IdentityUser>(this._session);
            var roleStore = new RoleStore<IdentityRole>(this._session);

            await roleStore.CreateAsync(role);
            await store.CreateAsync(user);
            await store.AddToRoleAsync(user, "ADM");

            Assert.True(await this._session.Query<IdentityRole>().AnyAsync(x => x.Name == "ADM"));
            Assert.True(await this._session.Query<IdentityUser>().AnyAsync(x => x.UserName == "Lukz 04"));

            var result = await store.DeleteAsync(user);

            Assert.True(result.Succeeded);
            Assert.Empty(result.Errors);
            Assert.False(await this._session.Query<IdentityUser>().AnyAsync(x => x.UserName == "Lukz 04"));
            Assert.True(await this._session.Query<IdentityRole>().AnyAsync(x => x.Name == "ADM"));
        }

        [Fact]
        public async Task WhenRemoveUserFromRole_ThenDoNotDeleteRole_BugFix()
        {
            var user = new IdentityUser("Lukz 05");
            var roleName = "ADM05";
            var role = new IdentityRole(roleName) { NormalizedName = this._normalizer.Normalize(roleName) };
            var store = new UserStore<IdentityUser>(this._session);
            var roleStore = new RoleStore<IdentityRole>(this._session);

            await roleStore.CreateAsync(role);
            await store.CreateAsync(user);
            await store.AddToRoleAsync(user, roleName);

            Assert.True(this._session.Query<IdentityRole>().Any(x => x.Name == roleName));
            Assert.True(this._session.Query<IdentityUser>().Any(x => x.UserName == "Lukz 05"));
            Assert.True(await store.IsInRoleAsync(user, roleName));

            var result = store.RemoveFromRoleAsync(user, roleName);

            Assert.Null(result.Exception);
            Assert.False(await store.IsInRoleAsync(user, roleName));
            Assert.True(this._session.Query<IdentityUser>().Any(x => x.UserName == "Lukz 05"));
            Assert.True(this._session.Query<IdentityRole>().Any(x => x.Name == roleName));
        }

        [Fact]
        public async Task GetAllUsers()
        {
            var user1 = new IdentityUser("Lukz 04");
            var user2 = new IdentityUser("Moa 01");
            var user3 = new IdentityUser("Win 02");
            var user4 = new IdentityUser("Andre 03");
            var role = new IdentityRole("ADM") { NormalizedName = "ADM" };
            var store = new UserStore<IdentityUser>(this._session);
            var roleStore = new RoleStore<IdentityRole>(this._session);

            await roleStore.CreateAsync(role);
            await store.CreateAsync(user1);
            await store.CreateAsync(user2);
            await store.CreateAsync(user3);
            await store.CreateAsync(user4);
            await store.AddToRoleAsync(user1, "ADM");
            await store.AddToRoleAsync(user2, "ADM");
            await store.AddToRoleAsync(user3, "ADM");
            await store.AddToRoleAsync(user4, "ADM");

            Assert.True(this._session.Query<IdentityRole>().Any(x => x.Name == "ADM"));
            Assert.True(this._session.Query<IdentityUser>().Any(x => x.UserName == "Lukz 04"));

            Assert.True(this._session.Query<IdentityUser>().Any(x => x.UserName == "Andre 03"));

            var resul = store.Users;

            Assert.Equal(4, resul.Count());
        }

        [Fact]
        public async Task GetAllRoles()
        {
            var user1 = new IdentityUser("Lukz 04");
            var user2 = new IdentityUser("Moa 01");
            var user3 = new IdentityUser("Win 02");
            var user4 = new IdentityUser("Andre 03");
            var role = new IdentityRole("ADM") { NormalizedName = "ADM" };
            var role2 = new IdentityRole("USR") { NormalizedName = "USR" };
            var store = new UserStore<IdentityUser>(this._session);
            var roleStore = new RoleStore<IdentityRole>(this._session);

            await roleStore.CreateAsync(role);
            await roleStore.CreateAsync(role2);
            await store.CreateAsync(user1);
            await store.CreateAsync(user2);
            await store.CreateAsync(user3);
            await store.CreateAsync(user4);
            await store.AddToRoleAsync(user1, "ADM");
            await store.AddToRoleAsync(user2, "ADM");
            await store.AddToRoleAsync(user3, "ADM");
            await store.AddToRoleAsync(user4, "ADM");
            await store.AddToRoleAsync(user1, "USR");
            await store.AddToRoleAsync(user4, "USR");

            Assert.True(this._session.Query<IdentityRole>().Any(x => x.Name == "ADM"));
            Assert.True(this._session.Query<IdentityUser>().Any(x => x.UserName == "Lukz 04"));

            Assert.True(this._session.Query<IdentityUser>().Any(x => x.UserName == "Andre 03"));

            var result = roleStore.Roles;

            Assert.Equal(2, result.Count());
        }

        [Fact]
        public async Task LockoutAccount()
        {
            this._userManager.Options.Lockout.MaxFailedAccessAttempts = 3;
            this._userManager.Options.Lockout.AllowedForNewUsers = true;
            this._userManager.Options.Lockout.DefaultLockoutTimeSpan = new TimeSpan(0, 10, 0);
            await this._userManager.CreateAsync(new ApplicationUser { UserName = "test", LockoutEnabled = true }, "Welcome");
            var user = await this._userManager.FindByNameAsync("test");
            Assert.Equal(0, await this._userManager.GetAccessFailedCountAsync(user));
            await this._userManager.AccessFailedAsync(user);
            Assert.Equal(1, await this._userManager.GetAccessFailedCountAsync(user));
            await this._userManager.AccessFailedAsync(user);
            Assert.Equal(2, await this._userManager.GetAccessFailedCountAsync(user));
            await this._userManager.AccessFailedAsync(user);
            Assert.True(await this._userManager.IsLockedOutAsync(user));
        }

        [Fact]
        public async Task FindByName()
        {
            await this._userManager.CreateAsync(new ApplicationUser { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true }, "Welcome");
            var x = await this._userManager.FindByNameAsync("tEsT");
            Assert.NotNull(x);
            Assert.True(await this._userManager.IsEmailConfirmedAsync(x));
        }

        [Fact]
        public async Task FindByNameWithRoles()
        {
            await this._roleManager.CreateAsync(new IdentityRole("Admin"));
            await this._roleManager.CreateAsync(new IdentityRole("AO"));
            var user = new ApplicationUser { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true };
            await this._userManager.CreateAsync(user, "Welcome");
            await this._userManager.AddToRoleAsync(user, "Admin");
            await this._userManager.AddToRoleAsync(user, "AO");
            // clear session
            this._session.Flush();
            this._session.Clear();

            var x = await this._userManager.FindByNameAsync("tEsT");
            Assert.NotNull(x);
            Assert.Equal(2, x.Roles.Count);
        }

        [Fact]
        public async Task FindByEmail()
        {
            await this._userManager.CreateAsync(new ApplicationUser { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true }, "Welcome");
            var x = await this._userManager.FindByEmailAsync("AaA@bBb.com");
            Assert.NotNull(x);
            Assert.True(await this._userManager.IsEmailConfirmedAsync(x));
        }

        [Fact]
        public async Task AddClaim()
        {
            var user = new ApplicationUser { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true };
            await this._userManager.CreateAsync(user, "Welcome");
            await this._userManager.AddClaimAsync(user, new Claim(ClaimTypes.Role, "Admin"));
            Assert.Equal(1, (await this._userManager.GetClaimsAsync(user)).Count);
        }

        [Fact]
        public async Task EmailConfirmationToken()
        {
            var tokenProvider = new EmailTokenProvider<ApplicationUser>();
            this._userManager.RegisterTokenProvider("Default", tokenProvider);
            await this._userManager.CreateAsync(new ApplicationUser { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = false }, "Welcome");
            var x = await this._userManager.FindByEmailAsync("aaa@bbb.com");
            var token = await this._userManager.GeneratePasswordResetTokenAsync(x);
            await this._userManager.ResetPasswordAsync(x, token, "Welcome!");
        }

        [Fact]
        public async Task FindByEmailAggregated()
        {
            await this._userManager.CreateAsync(new ApplicationUser { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true }, "Welcome");
            var x = await this._userManager.FindByEmailAsync("aaa@bbb.com");
            await this._roleManager.CreateAsync(new IdentityRole("Admin"));
            await this._userManager.AddClaimAsync(x, new Claim("role", "admin"));
            await this._userManager.AddClaimAsync(x, new Claim("role", "user"));
            await this._userManager.AddToRoleAsync(x, "Admin");
            await this._userManager.AddLoginAsync(x, new UserLoginInfo("facebook", "1234", "Facebook"));
            this._session.Clear();
            x = await this._userManager.FindByEmailAsync("aaa@bbb.com");
            Assert.NotNull(x);
            Assert.Equal(2, x.Claims.Count);
            Assert.Equal(1, x.Roles.Count);
            Assert.Equal(1, x.Logins.Count);
        }

        [Fact]
        public async Task CreateWithoutCommittingTransactionScopeShouldNotInsertRows()
        {
            using (var ts = new TransactionScope(TransactionScopeOption.RequiresNew, TransactionScopeAsyncFlowOption.Enabled))
            {
                // session is not opened inside the scope so we need to enlist it manually
                this._session.Connection.EnlistTransaction(System.Transactions.Transaction.Current);
                await this._userManager.CreateAsync(new ApplicationUser { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true }, "Welcome1");
                var x = await this._userManager.FindByEmailAsync("aaa@bbb.com");
                await this._roleManager.CreateAsync(new IdentityRole("Admin"));
                await this._userManager.AddClaimAsync(x, new Claim("role", "admin"));
                await this._userManager.AddClaimAsync(x, new Claim("role", "user"));
                await this._userManager.AddToRoleAsync(x, "Admin");
                await this._userManager.AddLoginAsync(x, new UserLoginInfo("facebook", "1234", "Facebook"));
            }
            var x2 = await this._userManager.FindByEmailAsync("aaa@bbb.com");
            Assert.Null(x2);
        }

        [Fact]
        public async Task CreateWithoutCommittingNHibernateTransactionShouldNotInsertRows()
        {
            using (var ts = this._session.BeginTransaction())
            {
                await this._userManager.CreateAsync(new ApplicationUser { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true }, "Welcome1");
                var x = await this._userManager.FindByEmailAsync("aaa@bbb.com");
                await this._roleManager.CreateAsync(new IdentityRole("Admin"));
                await this._userManager.AddClaimAsync(x, new Claim("role", "admin"));
                await this._userManager.AddClaimAsync(x, new Claim("role", "user"));
                await this._userManager.AddToRoleAsync(x, "Admin");
                await this._userManager.AddLoginAsync(x, new UserLoginInfo("facebook", "1234", "Facebook"));
            }
            var x2 = await this._userManager.FindByEmailAsync("aaa@bbb.com");
            Assert.Null(x2);
        }

        public void Dispose()
        {
            this._session?.Dispose();
            this._userManager?.Dispose();
            this._roleManager?.Dispose();
        }
    }
}
