// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System.Linq;
using System.Threading.Tasks;
using Garnet.server.ACL;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace Garnet.test.Resp.ACL
{
    /// <summary>
    /// Tests that operate in parallel on the ACL
    /// </summary>
    [TestFixture]
    internal class ParallelTests : AclTest
    {
        /// <summary>
        /// Creates and starts the Garnet test server
        /// </summary>
        [SetUp]
        public virtual void Setup()
        {
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, useAcl: true);
            server.Start();
        }

        /// <summary>
        /// Tests that AUTH works in parallel without corrupting the server state
        /// </summary>
        [TestCase(128, 2048)]
        public async Task ParallelAuthTest(int degreeOfParallelism, int iterationsPerSession)
        {
            using var c = TestUtils.GetGarnetClientSession();
            c.Connect();

            // Add the test user and password
            var response = await c.ExecuteAsync("ACL", "SETUSER", TestUserA, "on", $">{DummyPassword}");
            ClassicAssert.IsTrue(response.StartsWith("OK"));

            // Run multiple sessions that stress AUTH
            Parallel.For(0, degreeOfParallelism, (t, state) =>
            {
                using var c = TestUtils.GetGarnetClientSession();
                c.Connect();

                for (uint i = 0; i < iterationsPerSession; i++)
                {
                    // Execute two AUTH commands - one that succeeds and one that fails
                    c.Execute("AUTH", TestUserA, DummyPassword);
                    c.Execute("AUTH", DummyPasswordB);
                }
            });
        }

        /// <summary>
        /// Tests that password hashing works in parallel
        /// </summary>
        [TestCase(128, 2048)]
        public void ParallelPasswordHashTest(int degreeOfParallelism, int iterationsPerSession)
        {
            // Run multiple sessions that stress password hashing
            Parallel.For(0, degreeOfParallelism, (t, state) =>
            {
                for (uint i = 0; i < iterationsPerSession; i++)
                {
                    ACLPassword.ACLPasswordFromString(DummyPassword);
                    ACLPassword.ACLPasswordFromString(DummyPasswordB);
                }
            });
        }


        /// <summary>
        /// Tests that ACL SETUSER works in parallel without corrupting the user's ACL.
        /// Uses lower degrees of parallelism to reduce chances of deadlock.
        /// </summary>
        [TestCase(2, 2048)]
        public async Task ParallelAclSetUserTest2(int degreeOfParallelism, int iterationsPerSession)
        {
            string command1 = $"ACL SETUSER {TestUserA} on >{DummyPassword} +get";
            string command2 = $"ACL SETUSER {TestUserA} off >{DummyPassword} -get";

            string validResponse1 = $"user {TestUserA} on #{DummyPasswordHash} +get";
            string validResponse2 = $"user {TestUserA} off #{DummyPasswordHash} -get";
            string validResponse3 = $"user {TestUserA} off #{DummyPasswordHash}";

            var c = TestUtils.GetGarnetClientSession();
            c.Connect();
            _ = await c.ExecuteAsync(command1.Split(" "));

            // Run multiple sessions that stress AUTH
            await Parallel.ForAsync(0, degreeOfParallelism, async (t, state) =>
            {
                using var c = TestUtils.GetGarnetClientSession();
                c.Connect();

                for (uint i = 0; i < iterationsPerSession; i++)
                {

                    await Task.WhenAll(
                        c.ExecuteAsync(command1.Split(" ")),
                        c.ExecuteAsync(command2.Split(" ")));


                    //await c.ExecuteAsync(command1.Split(" "));
                    //await c.ExecuteAsync(command2.Split(" "));

                    var aclListResponse = await c.ExecuteForArrayAsync("ACL", "LIST");
                    if (!aclListResponse.Contains(validResponse1) && !aclListResponse.Contains(validResponse2) && !aclListResponse.Contains(validResponse3))
                    {
                        throw new AssertionException("Invalid ACL");
                    }
                }
            });
        }

        /// <summary>
        /// Tests that ACL SETUSER works in parallel without corrupting the user's ACL.
        /// Uses lower degrees of parallelism to reduce chances of deadlock.
        /// </summary>
        [TestCase(1, 2048)]
        public async Task ParallelAclSetUserTest(int degreeOfParallelism, int iterationsPerSession)
        {
            string command1 = $"ACL SETUSER {TestUserA} on >{DummyPassword} +get +set";
            // string command1 = $"ACL SETUSER {TestUserA} on >{DummyPassword} +@dangerous -@admin -get +set -setex +decr -decrby +incr -incrby +del -unlink +flushdb -latency";
            string command2 = $"ACL SETUSER {TestUserA} off >{DummyPassword} +get -set";
            // string command2 = $"ACL SETUSER {TestUserA} off >{DummyPassword} -@dangerous +@admin +get -set +setex -decr +decrby -incr +incrby -del +unlink -flushdb +latency";

            // string validResponse1 = $"user {TestUserA} on #{DummyPasswordHash} +@dangerous -@admin +set +decr +incr +del";
            string validResponse1 = $"user {TestUserA} on #{DummyPasswordHash} +get +set";
            // string validResponse2 = $"user {TestUserA} off #{DummyPasswordHash} +@admin +get +setex +decrby +incrby +unlink +latency";
            string validResponse2 = $"user {TestUserA} off #{DummyPasswordHash} +get";

            var c = TestUtils.GetGarnetClientSession();
            c.Connect();
            _ = await c.ExecuteAsync(command1.Split(" "));

            // Run multiple sessions that stress AUTH
            for (int t = 0; t < 100; t++)

            {
                /*
                using var c = TestUtils.GetGarnetClientSession();
                c.Connect();
                */

                for (uint i = 0; i < iterationsPerSession; i++)
                {
                    /*
                    await Task.WhenAll(
                        c.ExecuteAsync(command1.Split(" ")),
                        c.ExecuteAsync(command2.Split(" ")));
*/

                    await c.ExecuteAsync(command1.Split(" "));
                    await c.ExecuteAsync(command2.Split(" "));

                    var aclListResponse = await c.ExecuteForArrayAsync("ACL", "LIST");
                    if (!aclListResponse.Contains(validResponse1) && !aclListResponse.Contains(validResponse2))
                    {
                        throw new AssertionException("Invalid ACL");
                    }
                }
            }
        }

        /// <summary>
        /// Tests that ACL SETUSER works in parallel without fatal contention on user in authenticator map.
        /// Uses lower degrees of parallelism to reduce chances of deadlock.
        /// </summary>
        [TestCase(128, 2048)]
        public async Task ParallelAclSetUserAvoidsMapContentionTest(int degreeOfParallelism, int iterationsPerSession)
        {
            string command1 = $"ACL SETUSER {TestUserA} on >{DummyPassword} +@dangerous -@admin -get +set -setex +decr -decrby +incr -incrby +del -unlink +flushdb -latency";

            var c = TestUtils.GetGarnetClientSession();
            c.Connect();

            // Run multiple sessions that stress AUTH
            await Parallel.ForAsync(0, degreeOfParallelism, async (t, state) =>
            {
                using var c = TestUtils.GetGarnetClientSession();
                c.Connect();

                for (uint i = 0; i < iterationsPerSession; i++)
                {
                    await Task.WhenAll(c.ExecuteAsync(command1.Split(" ")));
                }
            });

            ClassicAssert.Pass();
        }

        /// <summary>
        /// Tests that ACL SETUSER works in parallel without encountering deadlocks. Test timesout after 5 minutes.
        /// </summary>
        [TestCase(128, 2048), CancelAfter(300000)]
        public async Task ParallelAclSetUserAvoidsDeadlockTest(int degreeOfParallelism, int iterationsPerSession)
        {
            string command1 = $"ACL SETUSER {TestUserA} on >{DummyPassword} -get +set";
            // string command1 = $"ACL SETUSER {TestUserA} on >{DummyPassword} +@dangerous -@admin -get +set -setex +decr -decrby +incr -incrby +del -unlink +flushdb -latency";
            string command2 = $"ACL SETUSER {TestUserA} off >{DummyPassword} +get -set";
            // string command2 = $"ACL SETUSER {TestUserA} off >{DummyPassword} -@dangerous +@admin +get -set +setex -decr +decrby -incr +incrby -del +unlink -flushdb +latency";

            // string validResponse1 = $"user {TestUserA} on #{DummyPasswordHash} +@dangerous -@admin +set +decr +incr +del";
            string validResponse1 = $"user {TestUserA} on #{DummyPasswordHash} +get -set";
            // string validResponse2 = $"user {TestUserA} off #{DummyPasswordHash} +@admin +get +setex +decrby +incrby +unlink +latency";
            string validResponse2 = $"user {TestUserA} off #{DummyPasswordHash} -get +set";

            var c = TestUtils.GetGarnetClientSession();
            c.Connect();
            _ = await c.ExecuteAsync(command1.Split(" "));

            // Run multiple sessions that stress AUTH
            await Parallel.ForAsync(0, degreeOfParallelism, async (t, state) =>
            {
                using var c = TestUtils.GetGarnetClientSession();
                c.Connect();

                for (uint i = 0; i < iterationsPerSession; i++)
                {
                    await Task.WhenAll(
                        c.ExecuteAsync(command1.Split(" ")),
                        c.ExecuteAsync(command2.Split(" ")));

                    _ = await c.ExecuteForArrayAsync("ACL", "LIST");
                }
            });

            var aclListResponse = await c.ExecuteForArrayAsync("ACL", "LIST");
            if (!aclListResponse.Contains(validResponse1) && !aclListResponse.Contains(validResponse2))
            {
                throw new AssertionException("Invalid ACL");
            }
        }
    }
}