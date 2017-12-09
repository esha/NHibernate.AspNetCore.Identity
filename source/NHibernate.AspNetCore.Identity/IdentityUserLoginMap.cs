using NHibernate.Mapping.ByCode.Conformist;

namespace NHibernate.AspNetCore.Identity
{
    public class IdentityUserLoginMap : ClassMapping<IdentityUserLogin>
    {
        public IdentityUserLoginMap()
        {
            this.Table("AspNetUserLogins");
            this.ComposedId(map =>
            {
                map.Property(t => t.LoginProvider);
                map.Property(t => t.ProviderKey);
            });
            this.Property(x => x.ProviderDisplayName, map =>
            {
                map.Length(256);
                map.NotNullable(true);
            });
            this.Property(x => x.UserId, map =>
            {
                map.Length(40);
            });
        }
    }
}