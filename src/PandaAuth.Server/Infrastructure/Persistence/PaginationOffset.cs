namespace PandaAuth.Server.Infrastructure.Persistence;

internal static class PaginationOffset
{
    // Page and page size have already been normalized to positive values by the caller.
    // EF accepts an Int32 offset; widen before multiplying so large pages cannot wrap.
    internal static int Calculate(int pageNumber, int pageSize)
        => (int)Math.Min(((long)pageNumber - 1) * pageSize, int.MaxValue);
}
