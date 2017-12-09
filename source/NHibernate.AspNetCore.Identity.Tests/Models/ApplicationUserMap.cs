using NHibernate.Mapping.ByCode.Conformist;

namespace NHibernate.AspNetCore.Identity.Tests.Models
{
    public class ApplicationUserMap : UnionSubclassMapping<ApplicationUser>
    {
        public ApplicationUserMap()
        {
            this.Extends(typeof(IdentityUser));
        }
    }
}