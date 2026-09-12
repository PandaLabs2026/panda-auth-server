# PandaAuth.Server 镜像（IDP 核心，生产绑定 127.0.0.1:9004）
#
# 跨仓构建：Server 通过相对路径引用 panda-auth-share，因此构建上下文必须是
# panda-auth 工作区根（五个仓库同级克隆）：
#   docker build -f panda-auth-server/Dockerfile .
# 上下文包含 bin/obj（各仓 .dockerignore 不生效于父上下文），仅影响缓存效率不影响产物。

# ================= 构建阶段 =================
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY panda-auth-share/ panda-auth-share/
COPY panda-auth-server/ panda-auth-server/
RUN dotnet restore panda-auth-server/PandaAuth.Server.slnx
RUN dotnet publish panda-auth-server/src/PandaAuth.Server -c Release -o /app --nologo

# ================= 运行阶段 =================
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

COPY --from=build /app .

# 只绑定回环地址，公网流量一律经宿主机 Caddy 反代（禁止 0.0.0.0 裸暴露）
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_URLS=http://127.0.0.1:9004

EXPOSE 9004

ENTRYPOINT ["dotnet", "PandaAuth.Server.dll"]
