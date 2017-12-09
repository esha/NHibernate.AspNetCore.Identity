using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;

namespace NHibernate.AspNetCore.Identity
{
    public class IdentityRoleMap : ClassMapping<IdentityRole>
    {
        public IdentityRoleMap()
        {
            this.Table("AspNetRoles");
            this.Id(x => x.Id, m => m.Generator(new UUIDHexCombGeneratorDef("D")));
            this.Property(x => x.Name, map =>
            {
                map.Length(255);
                map.NotNullable(true);
                map.Unique(true);
            });
            this.Property(x => x.NormalizedName, map =>
            {
                map.Length(255);
                map.NotNullable(true);
                map.Unique(true);
            });
            this.Bag(x => x.Users, map =>
            {
                map.Table("AspNetUserRoles");
                map.Cascade(Cascade.None);
                map.Key(k => k.Column("RoleId"));
            }, rel => rel.ManyToMany(p => p.Column("UserId")));
        }
    }
}