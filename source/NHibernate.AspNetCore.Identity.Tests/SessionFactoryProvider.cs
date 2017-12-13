using System;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Castle.Core.Internal;
using NHibernate.AspNetCore.Identity.Tests.Models;
using NHibernate.Cfg;
using NHibernate.Mapping.ByCode;
using NHibernate.Tool.hbm2ddl;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace NHibernate.AspNetCore.Identity.Tests
{
    [XunitTestCaseDiscoverer("NHibernate.AspNetCore.Identity.Tests.DbFactDiscoverer", "NHibernate.AspNetCore.Identity.Tests")]
    public class DbFactAttribute : FactAttribute
    {
    }

    public class DbFactDiscoverer : IXunitTestCaseDiscoverer
    {
        private readonly IMessageSink _diagnosticMessageSink;
        public DbFactDiscoverer(IMessageSink diagnosticMessageSink)
        {
            this._diagnosticMessageSink = diagnosticMessageSink;
        }

        public IEnumerable<IXunitTestCase> Discover(ITestFrameworkDiscoveryOptions discoveryOptions, ITestMethod testMethod, IAttributeInfo factAttribute)
        {
            yield return new DbFactTestCase(this._diagnosticMessageSink, discoveryOptions.MethodDisplayOrDefault(), testMethod);
        }
    }

    public class DbFactTestCase : XunitTestCase
    {
        [Obsolete("Called by the de-serializer; should only be called by deriving classes for de-serialization purposes")]
        public DbFactTestCase() { }

        public DbFactTestCase(IMessageSink diagnosticMessageSink, TestMethodDisplay defaultMethodDisplay, ITestMethod testMethod, object[] testMethodArguments = null)
            : base(diagnosticMessageSink, defaultMethodDisplay, testMethod, testMethodArguments) { }

        public override async Task<RunSummary> RunAsync(IMessageSink diagnosticMessageSink,
            IMessageBus messageBus,
            object[] constructorArguments,
            ExceptionAggregator aggregator,
            CancellationTokenSource cancellationTokenSource)
        {
            // The constructorArguments can be replaced here to include the name of the test method to the ctor of the test class
            //constructorArguments = new object[] {this.TestMethod.Method.Name};
            var result = await base.RunAsync(diagnosticMessageSink, messageBus, constructorArguments, aggregator, cancellationTokenSource);
            return result;
        }
    }

    public sealed class SessionFactoryProvider
    {
        private static volatile SessionFactoryProvider _instance;
        private static readonly object _syncRoot = new Object();
        private readonly Configuration _configuration;

        public ISessionFactory SessionFactory { get; }

        private SessionFactoryProvider()
        {
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

        public void BuildSchema(DbConnection connection = null)
        {
            var path = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                $@"schema{connection?.DataSource}.sql");

            // this NHibernate tool takes a configuration (with mapping info in)
            // and exports a database schema from it
            var schemaExport = new SchemaExport(this._configuration);
            schemaExport.SetOutputFile(path);
            schemaExport.Create(
                useStdOut: true,
                execute: false);

            if (connection != null)
            {
                schemaExport.Execute(
                    useStdOut: false,
                    execute: true,
                    justDrop: false,
                    connection: connection,
                    exportOutput: null);
            }
            else
            {
                schemaExport.Execute(
                    useStdOut: false,
                    execute: true,
                    justDrop: false);
            }
        }
    }
}
