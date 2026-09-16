# PandaAuth.Server 镜像（IDP 核心，生产绑定 127.0.0.1:9004）
#
# 跨仓构建：Server 通过相对路径引用 panda-auth-share，因此构建上下文必须是
# panda-auth 工作区根（五个仓库同级克隆）：
#   docker build -f panda-auth-server/Dockerfile .
# 上下文过滤走同目录的 Dockerfile.dockerignore（BuildKit 按 Dockerfile 名取用，
# 模式相对上下文根=工作区根）：本仓 .dockerignore 对父上下文不生效，此前 bin/obj
# 会整体进入上下文，让构建结果随构建机本地状态漂移。

# ================= 构建阶段 =================
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY panda-auth-share/ panda-auth-share/
COPY panda-auth-server/ panda-auth-server/
RUN dotnet restore panda-auth-server/PandaAuth.Server.slnx
RUN dotnet publish panda-auth-server/src/PandaAuth.Server -c Release -o /app --nologo

# ================= 运行阶段 =================
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# 非 root 运行：aspnet 基础镜像自带 uid 1654 的 app 用户
COPY --chown=app:app --from=build /app .

# DataProtection 密钥目录必须在镜像里预建并归 app 所有：命名卷首次创建时继承的是镜像内
# 该路径的属主，目录缺失或属 root 时 app 写不进密钥，启动即失败（compose 挂载了本路径）。
RUN mkdir -p /var/lib/panda-auth/dataprotection \
    && chown app:app /var/lib/panda-auth/dataprotection

# 只绑定回环地址，公网流量一律经宿主机 Caddy 反代（禁止 0.0.0.0 裸暴露）
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_URLS=http://127.0.0.1:9004

EXPOSE 9004

# 镜像级探活；compose 的 healthcheck 会覆盖它，属双保险
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:9004/healthz || exit 1

USER app

ENTRYPOINT ["dotnet", "PandaAuth.Server.dll"]
