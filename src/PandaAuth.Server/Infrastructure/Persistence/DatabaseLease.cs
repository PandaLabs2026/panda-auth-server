using System.Diagnostics;
using Npgsql;

namespace PandaAuth.Server.Infrastructure.Persistence;

/// <summary>
/// 每库单一租约（PG advisory lock）：把「查-生成-写」形态的初始化临界区——迁移+种子、
/// 签名密钥生成——按库串行化，同库并发首启不再依赖外部 provision 锁
/// （设计依据：元仓 docs/design/fleet-control-plane.md 第六节 co-tenancy 审计）。
/// 锁键取 hashtext(current_database())，按库天然隔离；获取超时失败关闭——宁可
/// crash-loop 大声报错，也不允许双进程并发生成签名密钥或交错执行迁移。
/// </summary>
internal static class DatabaseLease
{
    /// <summary>
    /// 租约族常量（两键 advisory lock 的第二键，int4）：隔离本应用与宿主上其它 advisory
    /// lock 用户的键空间；配合 hashtext(current_database())（int4）形成每库唯一键。
    /// 注意双键形式是 (int4, int4)——第二键传 long 会命中不存在的 (int4, int8) 重载。
    /// </summary>
    private const int LeaseFamily = unchecked((int)0x50414441); // "PADA"

    /// <summary>默认等待上界：合法迁移可能耗时数分钟，排队等待而非立即失败；超时意味着
    /// 同库存在长期持锁者或锁泄漏，继续排队只会让编排层（compose/agent）的健康探测悬空。</summary>
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(5);

    /// <summary>获取当前数据库的初始化租约。返回的租约释放前，同库其它获取方一律阻塞。</summary>
    public static async Task<IAsyncDisposable> AcquireAsync(
        string connectionString, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        var wait = timeout ?? DefaultTimeout;
        var connection = new NpgsqlConnection(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            var started = Stopwatch.StartNew();
            while (!await TryAcquireOnceAsync(connection, cancellationToken))
            {
                if (started.Elapsed >= wait)
                {
                    throw new InvalidOperationException(
                        $"数据库初始化租约获取超时（等待 {wait.TotalSeconds:0} 秒）：同库存在其它迁移/首启进程长期持锁，拒绝并发初始化。");
                }
                await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
            }
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
        return new Lease(connection);
    }

    private static async Task<bool> TryAcquireOnceAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        using var command = new NpgsqlCommand(
            "SELECT pg_try_advisory_lock(hashtext(current_database()), $1)", connection);
        command.Parameters.AddWithValue(LeaseFamily);
        return await command.ExecuteScalarAsync(cancellationToken) is true;
    }

    private sealed class Lease(NpgsqlConnection connection) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            try
            {
                using var command = new NpgsqlCommand(
                    "SELECT pg_advisory_unlock(hashtext(current_database()), $1)", connection);
                command.Parameters.AddWithValue(LeaseFamily);
                await command.ExecuteScalarAsync();
            }
            finally
            {
                // 连接关闭兜底：会话级 advisory lock 随会话终止必然释放，防解锁语句异常时泄漏。
                await connection.DisposeAsync();
            }
        }
    }
}
