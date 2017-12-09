using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using NHibernate.AspNetCore.Identity.Properties;
using NHibernate.Linq;

namespace NHibernate.AspNetCore.Identity
{
    /// <summary>
    /// Implements IUserStore using NHibernate where TUser is the entity type of the user being stored
    /// </summary>
    /// <typeparam name="TUser"/>
    public class UserStore<TUser> : UserStoreBase<TUser, string, IdentityUserClaim, IdentityUserLogin, IdentityUserToken<string>>, IUserRoleStore<TUser>
        where TUser : IdentityUser
    {
        /// <summary>
        /// If true then disposing this object will also dispose (close) the session. False means that external code is responsible for disposing the session.
        /// </summary>
        public bool ShouldDisposeSession { get; set; }

        public ISession Context { get; }

        public UserStore(ISession context)
            : base(new IdentityErrorDescriber())
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            this.ShouldDisposeSession = true;
            this.Context = context;
        }

        public override Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            //return Task.FromResult(this.Context.Get<TUser>((object)userId));
            return this.GetUserAggregateAsync(u => u.Id.Equals(userId));
        }

        public override Task<TUser> FindByNameAsync(string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            //return Task.FromResult<TUser>(Queryable.FirstOrDefault<TUser>(Queryable.Where<TUser>(this.Context.Query<TUser>(), (Expression<Func<TUser, bool>>)(u => u.UserName.ToUpper() == userName.ToUpper()))));
            return this.GetUserAggregateAsync(u => u.UserName.ToUpper() == userName.ToUpper());
        }

        protected override async Task<TUser> FindUserAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(userId));

            return await this.Context.GetAsync<TUser>(userId, cancellationToken);
        }

        protected override async Task<IdentityUserLogin> FindUserLoginAsync(string userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(userId));
            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(providerKey));

            var query = from u in this.Users
                        where u.Id == userId
                        from l in u.Logins
                        where l.LoginProvider == loginProvider && l.ProviderKey == providerKey
                        select l;

            return await query.SingleOrDefaultAsync(cancellationToken);
        }

        protected override async Task<IdentityUserLogin> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(providerKey));

            var query = from u in this.Users
                        from l in u.Logins
                        where l.LoginProvider == loginProvider && l.ProviderKey == providerKey
                        select l;

            return await query.SingleOrDefaultAsync(cancellationToken);
        }

        public override Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            this.Context.Save(user);
            this.Context.Flush();

            return Task.FromResult(IdentityResult.Success);
        }

        public override Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            this.Context.Delete(user);
            this.Context.Flush();

            return Task.FromResult(IdentityResult.Success);
        }

        public override async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            this.Context.Flush();

            return IdentityResult.Success;
        }

        public override async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (login == null)
                throw new ArgumentNullException(nameof(login));

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            user.AddLogin(new IdentityUserLogin
            {
                ProviderKey = login.ProviderKey,
                LoginProvider = login.LoginProvider,
                ProviderDisplayName = login.ProviderDisplayName
            });

            await this.Context.FlushAsync(cancellationToken);
        }

        public override async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentException(nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentException(nameof(providerKey));

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            var login = user.Logins?.SingleOrDefault(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey);
            if (login != null)
            {
                user.RemoveLogin(login);
                await this.Context.FlushAsync(cancellationToken);
            }
        }
        
        public override Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            IList<UserLoginInfo> result = (user.Logins?.Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, user.UserName)) ?? Enumerable.Empty<UserLoginInfo>()).ToList();
            return Task.FromResult(result);
        }

        public override Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            IList<Claim> result = (user.Claims?.Select(c => new Claim(c.ClaimType, c.ClaimValue)) ?? Enumerable.Empty<Claim>()).ToList();
            return Task.FromResult(result);
        }

        public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claims == null)
                throw new ArgumentNullException(nameof(claims));
            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            foreach (var claim in claims)
            {
                user.AddClaim(new IdentityUserClaim
                {
                    ClaimType = claim.Type,
                    ClaimValue = claim.Value,
                    User = user,
                    UserId = user.Id
                });
            }
            await this.Context.FlushAsync(cancellationToken);
        }

        public override async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));
            if (newClaim == null)
                throw new ArgumentNullException(nameof(newClaim));

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            var userClaims = user.Claims;
            var matchedClaims = (userClaims?.Where(uc => uc.UserId.Equals(user.Id) && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type) ?? Enumerable.Empty<IdentityUserClaim>()).ToList();
            foreach (var matchedClaim in matchedClaims)
            {
                matchedClaim.ClaimValue = newClaim.Value;
                matchedClaim.ClaimType = newClaim.Type;
            }

            await this.Context.FlushAsync(cancellationToken);
        }

        public override async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claimsToRemove, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claimsToRemove == null)
                throw new ArgumentNullException(nameof(claimsToRemove));

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            var toRemoveList = claimsToRemove.ToList();
            var removeSet = user.Claims?.Where(c => toRemoveList.Any(r => r.Type == c.ClaimType && r.Value == c.ClaimValue)).ToList();
            if (removeSet != null)
            {
                removeSet.ForEach(c => user.Claims.Remove(c));
                await this.Context.FlushAsync(cancellationToken);
            }
        }

        public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            var query = from userClaim in this.Context.Query<IdentityUserClaim>()
                        join user in this.Users on userClaim.UserId equals user.Id
                        where userClaim.ClaimValue == claim.Value && userClaim.ClaimType == claim.Type
                        select user;

            return await query.ToListAsync(cancellationToken);
        }

        // ReSharper disable once OptionalParameterHierarchyMismatch
        protected override async Task<IdentityUserToken<string>> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentException(nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException(nameof(name));

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            var token = user?.Tokens.SingleOrDefault(t => t.Name == name && t.LoginProvider == loginProvider);
            return token;
        }

        protected override async Task AddUserTokenAsync(IdentityUserToken<string> token)
        {
            this.ThrowIfDisposed();
            if (token == null)
                throw new ArgumentNullException(nameof(token));
            var user = (IdentityUser)await this.Context.GetAsync(typeof(IdentityUser), token.UserId);
            user.AddToken(token);
            await this.Context.FlushAsync();
        }

        protected override async Task RemoveUserTokenAsync(IdentityUserToken<string> token)
        {
            this.ThrowIfDisposed();
            if (token == null)
                throw new ArgumentNullException(nameof(token));
            var user = (IdentityUser)await this.Context.GetAsync(typeof(IdentityUser), token.UserId);
            user.RemoveToken(token);
            await this.Context.FlushAsync();
        }

        public virtual async Task AddToRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(normalizedRoleName));

            var roleEntity = await this.Context.Query<IdentityRole>().SingleOrDefaultAsync(r => r.NormalizedName == normalizedRoleName, cancellationToken);
            if (roleEntity == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.RoleNotFound, normalizedRoleName));
            }

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            user.AddRole(roleEntity);
            await this.Context.FlushAsync(cancellationToken);
        }

        public virtual async Task RemoveFromRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(normalizedRoleName));

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            var identityUserRole = user.Roles.FirstOrDefault(r => r.NormalizedName == normalizedRoleName);
            if (identityUserRole != null)
            {
                user.RemoveRole(identityUserRole);
            }

            await this.Context.FlushAsync(cancellationToken);
        }

        public virtual async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            return user.Roles?.Select(u => u.Name).ToList();
        }

        public virtual async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(normalizedRoleName));

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
            return user.Roles?.Any(r => r.NormalizedName == normalizedRoleName) ?? false;
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            if (string.IsNullOrEmpty(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            var role = await this.Context.Query<IdentityRole>().Where(r => r.NormalizedName == normalizedRoleName)
                .SingleOrDefaultAsync(cancellationToken);

            if (role == null)
                return new List<TUser>();

            var query = from user in this.Users
                        where user.Roles.Any(r => r == role)
                        select user;

            return await query.ToListAsync(cancellationToken);
        }

        public override IQueryable<TUser> Users
        {
            get
            {
                this.ThrowIfDisposed();
                return this.Context.Query<TUser>();
            }
        }

        public override Task<TUser> FindByEmailAsync(string email, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            return this.GetUserAggregateAsync(u => u.Email.ToUpper() == email.ToUpper());
        }

        private Task<TUser> GetUserAggregateAsync(Expression<Func<TUser, bool>> filter)
        {
            return Task.Run(() =>
            {
                // no cartesian product, batch call. Don't know if it's really needed: should we eager load or let lazy loading do its stuff?
                var query = this.Context.Query<TUser>().Where(filter);
                query.Fetch(p => p.Roles).ToFuture();
                query.Fetch(p => p.Claims).ToFuture();
                query.Fetch(p => p.Logins).ToFuture();
                return query.ToFuture().FirstOrDefault();
            });
        }
    }
}
