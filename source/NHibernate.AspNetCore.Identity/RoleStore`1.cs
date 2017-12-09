using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace NHibernate.AspNetCore.Identity
{
    public class RoleStore<TRole> : IQueryableRoleStore<TRole> where TRole : IdentityRole
    {
        private bool _disposed;

        /// <summary>
        /// If true then disposing this object will also dispose (close) the session. False means that external code is responsible for disposing the session.
        /// </summary>
        public bool ShouldDisposeSession { get; set; }

        public ISession Context { get; private set; }

        public RoleStore(ISession context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            ShouldDisposeSession = true;
            this.Context = context;
        }

        public virtual Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            return Task.FromResult(Context.Get<TRole>(roleId));
        }

        public virtual Task<TRole> FindByNameAsync(string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            return Task.FromResult(this.Context.Query<TRole>().FirstOrDefault(u => u.Name.ToUpper() == roleName.ToUpper()));
        }

        public virtual Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));
            Context.Save(role);
            Context.Flush();
            return Task.FromResult(IdentityResult.Success);
        }

        public virtual Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));

            Context.Delete(role);
            Context.Flush();
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.Id);
        }

        public async Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            if (role.Name != null)
                return role.Name;

            var roleName = ((TRole)await Context.GetAsync(typeof(TRole), role.Id, cancellationToken)).Name;
            return roleName;
        }

        public Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));

            role.Name = roleName;
            return Task.CompletedTask;
        }

        public Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));
            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        public async Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));
            if (role.NormalizedName != null)
                return role.NormalizedName;

            var normalizedName = ((TRole)await Context.GetAsync(typeof(TRole), role.Id, cancellationToken)).NormalizedName;
            return normalizedName;
        }

        public virtual Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            this.ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));
            Context.Update(role);
            Context.Flush();
            return Task.FromResult(IdentityResult.Success);
        }

        private void ThrowIfDisposed()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().Name);
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing && !this._disposed && ShouldDisposeSession)
                this.Context.Dispose();
            this._disposed = true;
            this.Context = null;
        }

        public IQueryable<TRole> Roles
        {
            get
            {
                this.ThrowIfDisposed();
                return this.Context.Query<TRole>();
            }
        }
    }
}
