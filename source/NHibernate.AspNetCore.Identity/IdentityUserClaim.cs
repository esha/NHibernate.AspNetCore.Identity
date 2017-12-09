using Microsoft.AspNetCore.Identity;

namespace NHibernate.AspNetCore.Identity
{
    public class IdentityUserClaim : IdentityUserClaim<string>
    {
        public virtual IdentityUser User { get; set; }
    }
}
