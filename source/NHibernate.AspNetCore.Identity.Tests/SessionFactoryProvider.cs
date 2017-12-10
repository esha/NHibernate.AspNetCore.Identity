using System;
using System.IO;
using NHibernate.AspNetCore.Identity.Tests.Models;
using NHibernate.Cfg;
using NHibernate.Mapping.ByCode;
using NHibernate.Tool.hbm2ddl;

namespace NHibernate.AspNetCore.Identity.Tests
{
    public sealed class SessionFactoryProvider
    {
        private static volatile SessionFactoryProvider _instance;
        private static readonly object _syncRoot = new Object();
        private readonly Configuration _configuration;

        public ISessionFactory SessionFactory { get; }
        public string Name { get; }

        /// <summary>
        /// constructor configures a SessionFactory based on the configuration passed in
        /// </summary>
        private SessionFactoryProvider()
        {
            Name = "NHibernate.AspNetCore.Identity";

            var allEntities = new[] { 
                typeof(IdentityUser), 
                typeof(ApplicationUser), 
                typeof(IdentityRole), 
                typeof(IdentityUserClaim),
                typeof(IdentityUserToken),
                typeof(IdentityUserLogin),
                typeof(Foo)
            };

            var mapper = new ModelMapper();
            mapper.AddMapping<ApplicationUserMap>();
            mapper.AddMapping<IdentityUserMap>();
            mapper.AddMapping<IdentityRoleMap>();
            mapper.AddMapping<IdentityUserClaimMap>();
            mapper.AddMapping<IdentityUserTokenMap>();
            mapper.AddMapping<IdentityUserLoginMap>();
            mapper.AddMapping<FooMap>();

            var mapping = mapper.CompileMappingForEach(allEntities);

            this._configuration = new Configuration();
            this._configuration.Configure("sqlite-nhibernate-config.xml");
            foreach (var map in mapping)
            {
                Console.WriteLine(map.AsString());
                this._configuration.AddDeserializedMapping(map, null);
            }
            this.SessionFactory = this._configuration.BuildSessionFactory();
        }

        public static SessionFactoryProvider Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_syncRoot)
                    {
                        if (_instance == null)
                            _instance = new SessionFactoryProvider();
                    }
                }
                return _instance;
            }
        }

        public void BuildSchema()
        {
            var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"schema.sql");

            // this NHibernate tool takes a configuration (with mapping info in)
            // and exports a database schema from it
            new SchemaExport(_configuration)
                .SetOutputFile(path)
                .Create(true, true /* DROP AND CREATE SCHEMA */);
        }
    }
}
