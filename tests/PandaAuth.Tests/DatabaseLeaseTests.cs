using System.Data;
using Npgsql;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// 每库单一租约语义（隔离 PostgreSQL）：互斥、释放后可再取、超时失败关闭。
/// Program.cs 的两个临界区（--migrate、签名密钥加载）是薄接线；本文件锁的是
/// 租约机制本身——并发首启的正确性完全依赖这三个语义。
/// </summary>
public class DatabaseLeaseTests
{
    [PostgresFact]
    public async Task SecondAcquirer_WhileLeaseHeld_TimesOutInsteadOfEntering()
    {
        await using var database = await TestDatabase.CreateAsync();

        var first = await DatabaseLease.AcquireAsync(database.ConnectionString, TimeSpan.FromSeconds(5));

        var second = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DatabaseLease.AcquireAsync(database.ConnectionString, TimeSpan.FromSeconds(1)));
        Assert.Contains("租约获取超时", second.Message);

        await first.DisposeAsync();
    }

    [PostgresFact]
    public async Task ReleasedLease_CanBeReacquired_ByAnotherSession()
    {
        await using var database = await TestDatabase.CreateAsync();

        var first = await DatabaseLease.AcquireAsync(database.ConnectionString, TimeSpan.FromSeconds(5));
        await first.DisposeAsync();

        await using var second = await DatabaseLease.AcquireAsync(database.ConnectionString, TimeSpan.FromSeconds(5));
    }

    [PostgresFact]
    public async Task ConcurrentAcquirers_AreSerialized_NotRejected()
    {
        await using var database = await TestDatabase.CreateAsync();

        // 两个并发获取方都应最终成功（排队等待），而非第二个直接失败——
        // 对应真实场景：第二个 --migrate 排队等第一个完成后照常执行（幂等）。
        var gate = new TaskCompletionSource();
        var firstTask = Task.Run(async () =>
        {
            var lease = await DatabaseLease.AcquireAsync(database.ConnectionString, TimeSpan.FromSeconds(10));
            await gate.Task;
            await lease.DisposeAsync();
        });
        await Task.Delay(300);
        var secondTask = DatabaseLease.AcquireAsync(database.ConnectionString, TimeSpan.FromSeconds(10));

        gate.SetResult();
        await Task.WhenAll(firstTask, (await secondTask).DisposeAsync().AsTask());
    }

    private sealed class TestDatabase : IAsyncDisposable
    {
        internal string ConnectionString { get; private init; } = string.Empty;

        internal static async Task<TestDatabase> CreateAsync()
        {
            var admin = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"));
            if (admin.Host != "127.0.0.1" || admin.Port != 43823 || admin.Database != "postgres")
                throw new InvalidOperationException("Auth protocol fixture requires the approved task loopback cluster/admin database.");
            var name = "panda_protocol_test_" + Guid.NewGuid().ToString("N");
            await using (var connection = new NpgsqlConnection(admin.ConnectionString))
            {
                await connection.OpenAsync();
                await using var create = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", connection);
                await create.ExecuteNonQueryAsync();
            }
            admin.Database = name;
            return new TestDatabase { ConnectionString = admin.ConnectionString };
        }

        public async ValueTask DisposeAsync()
        {
            var builder = new NpgsqlConnectionStringBuilder(ConnectionString);
            if (builder.Host != "127.0.0.1" || builder.Port != 43823 ||
                builder.Database is null || !System.Text.RegularExpressions.Regex.IsMatch(
                    builder.Database, "^panda_protocol_test_[0-9a-f]{32}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant))
                throw new InvalidOperationException("Refusing cleanup outside this task-owned Auth database.");
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(
                new NpgsqlConnectionStringBuilder(ConnectionString) { Database = "postgres" }.ConnectionString);
            await connection.OpenAsync();
            await using var drop = new NpgsqlCommand($"DROP DATABASE \"{builder.Database}\" WITH (FORCE)", connection);
            await drop.ExecuteNonQueryAsync();
        }
    }
}
